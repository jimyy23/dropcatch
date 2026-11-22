// Command dropcatch is the domain monitor / drop-catch server.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"dropcatch/internal/config"
	"dropcatch/internal/engine"
	"dropcatch/internal/monitor"
	"dropcatch/internal/notify"
	"dropcatch/internal/pricing"
	"dropcatch/internal/registrar"
	"dropcatch/internal/settings"
	"dropcatch/internal/store"
	"dropcatch/internal/web"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		healthcheck()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "user" {
		userCmd(os.Args[2:])
		return
	}
	env := config.Load()
	level := slog.LevelInfo
	switch strings.ToLower(env.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	st, err := store.Open(env.DBPath)
	if err != nil {
		log.Error("open db", "path", env.DBPath, "err", err)
		os.Exit(1)
	}
	defer st.Close()
	if env.AdminUser != "" && env.AdminPassword != "" && st.CountUsers() == 0 {
		if _, err := st.CreateUser(env.AdminUser, env.AdminPassword); err != nil {
			log.Error("bootstrap admin from env failed", "err", err)
		} else {
			log.Info("created initial admin from environment", "user", env.AdminUser)
		}
	}

	netim := registrar.NewNetim(env.Netim, env.OrdersDryRun)
	defer netim.Close()
	regs := registrar.NewSet(
		registrar.NewDynadot(env.Dynadot, env.Contact, env.OrdersDryRun),
		registrar.NewPorkbun(env.Porkbun, env.OrdersDryRun),
		registrar.NewInternetBS(env.InternetBS, env.Contact, env.OrdersDryRun),
		netim,
		registrar.NewCloudflare(env.Cloudflare, env.OrdersDryRun),
		registrar.NewRegery(env.Regery, env.Contact, env.OrdersDryRun),
		registrar.NewNameSilo(env.NameSilo, env.Contact, env.OrdersDryRun),
	)
	for _, r := range regs.All() {
		switch {
		case !r.Configured():
			log.Info("registrar not configured", "registrar", r.Label())
		case r.Problem() != "":
			log.Warn("registrar configured but incomplete", "registrar", r.Label(), "problem", r.Problem())
		default:
			log.Info("registrar ready", "registrar", r.Label())
		}
	}
	if env.OrdersDryRun {
		log.Warn("ORDERS_DRY_RUN=true: no real orders will be placed")
	}

	mon := monitor.NewManager(st)
	// Sources keep their rate-limit state across settings changes.
	cloudean := monitor.NewCloudean(30*time.Second, time.Second, 4)
	regery := monitor.NewRegery(30*time.Second, 60)
	whois := monitor.NewWhois(env.WhoisURL, env.WhoisPassword, 40*time.Second, 2*time.Second)
	var regSources []*monitor.RegistrarSource
	for _, r := range regs.Ready() {
		regSources = append(regSources, monitor.NewRegistrarSource(r, 2*time.Second, 60))
	}
	applyMonitor := func() {
		if whois != nil {
			whois.SetGap(time.Duration(settings.Int(st, "whois_gap_ms")) * time.Millisecond)
			whois.SetTimeout(settings.Secs(st, "whois_timeout_s"))
		}
		cloudean.SetGap(time.Duration(settings.Int(st, "cloudean_gap_ms")) * time.Millisecond)
		regery.SetPerHour(settings.Int(st, "regery_per_hour"))
		for _, s := range regSources {
			s.SetPerHour(settings.Int(st, "registrar_checks_per_hour"))
		}
		mon.Configure(settings.MonitorConfig(st), whois, []monitor.Source{cloudean, regery}, regSources)
	}
	applyMonitor()
	if w := mon.Whois(); w != nil {
		go func() {
			c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if err := w.Ping(c); err != nil {
				log.Warn("whois service not reachable", "url", w.BaseURL(), "err", err)
			} else {
				log.Info("whois service reachable", "url", w.BaseURL())
			}
		}()
	} else {
		log.Warn("WHOIS_URL not set: monitoring uses fallbacks only")
	}

	note := notify.New(env.Twilio, env.Telegram)
	price := pricing.New(st, time.Duration(settings.Int(st, "pricing_ttl_hours"))*time.Hour)
	eng := engine.New(st, mon, regs, note, price, log)
	eng.SetConfig(settings.EngineConfig(st))

	srv := &web.Server{St: st, Eng: eng, Env: env, Log: log}
	srv.ApplySettings = func() {
		applyMonitor()
		price.SetTTL(time.Duration(settings.Int(st, "pricing_ttl_hours")) * time.Hour)
		eng.SetConfig(settings.EngineConfig(st))
	}
	h, err := srv.Handler()
	if err != nil {
		log.Error("web init", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go eng.Run(ctx)
	go refreshPrices(ctx, st, price, log)

	hs := &http.Server{Addr: env.Listen, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 180 * time.Second, IdleTimeout: 120 * time.Second}
	go func() {
		log.Info("listening", "addr", env.Listen, "db", env.DBPath)
		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http", "err", err)
			stop()
		}
	}()
	<-ctx.Done()
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hs.Shutdown(sctx)
}

// refreshPrices keeps the registrar-support cache warm for monitored suffixes.
func refreshPrices(ctx context.Context, st *store.Store, p *pricing.Service, log *slog.Logger) {
	for {
		for _, sfx := range st.Suffixes() {
			c, cancel := context.WithTimeout(ctx, time.Minute)
			if _, err := p.Get(c, sfx, false); err != nil {
				log.Warn("suffix pricing refresh failed", "suffix", sfx, "err", err)
			}
			cancel()
			if ctx.Err() != nil {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

func healthcheck() {
	addr := config.Load().Listen
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		os.Exit(1)
	}
}

// userCmd: dropcatch user create <username> <password> | dropcatch user reset-password <username> <password>
func userCmd(a []string) {
	env := config.Load()
	st, err := store.Open(env.DBPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer st.Close()
	switch {
	case len(a) == 3 && a[0] == "create":
		if _, err := st.CreateUser(a[1], a[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("created", a[1])
	case len(a) == 3 && a[0] == "reset-password":
		var id int64
		if err := st.R.QueryRow(`SELECT id FROM users WHERE username=?`, a[1]).Scan(&id); err != nil {
			fmt.Fprintln(os.Stderr, "no such user")
			os.Exit(1)
		}
		if err := st.SetPassword(id, a[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		st.SetUserActive(id, true)
		fmt.Println("password reset for", a[1])
	default:
		fmt.Fprintln(os.Stderr, "usage: dropcatch user create <username> <password>\n       dropcatch user reset-password <username> <password>")
		os.Exit(2)
	}
}
