// Package notify sends alerts through Twilio voice calls and Telegram.
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"dropcatch/internal/config"
)

// Notifier holds both optional channels.
type Notifier struct {
	tw   config.Twilio
	tg   config.Telegram
	http *http.Client
}

func New(tw config.Twilio, tg config.Telegram) *Notifier {
	return &Notifier{tw: tw, tg: tg, http: &http.Client{Timeout: 20 * time.Second}}
}

func (n *Notifier) CallConfigured() bool {
	return n.tw.AccountSID != "" && n.tw.AuthToken != "" && n.tw.From != "" && len(n.tw.To) > 0
}

func (n *Notifier) TelegramConfigured() bool { return n.tg.BotToken != "" && len(n.tg.ChatIDs) > 0 }

// Call places a voice call to every TWILIO_TO number, reading msg twice.
// Uses POST /2010-04-01/Accounts/{sid}/Calls.json with inline TwiML.
func (n *Notifier) Call(ctx context.Context, msg string) error {
	if !n.CallConfigured() {
		return errors.New("twilio not configured")
	}
	say := html.EscapeString(msg)
	twiml := `<Response><Say voice="alice">` + say + `</Say><Pause length="1"/><Say voice="alice">` + say + `</Say></Response>`
	var errs []string
	for _, to := range n.tw.To {
		form := url.Values{"To": {to}, "From": {n.tw.From}, "Twiml": {twiml}}
		req, _ := http.NewRequestWithContext(ctx, "POST", "https://api.twilio.com/2010-04-01/Accounts/"+url.PathEscape(n.tw.AccountSID)+"/Calls.json", strings.NewReader(form.Encode()))
		req.SetBasicAuth(n.tw.AccountSID, n.tw.AuthToken)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := n.http.Do(req)
		if err != nil {
			errs = append(errs, to+": "+err.Error())
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			var e struct {
				Message string `json:"message"`
			}
			json.Unmarshal(b, &e)
			errs = append(errs, fmt.Sprintf("%s: HTTP %d %s", to, resp.StatusCode, e.Message))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// Telegram sends msg (plain text) to every TELEGRAM_CHAT_IDS chat.
func (n *Notifier) Telegram(ctx context.Context, msg string) error {
	if !n.TelegramConfigured() {
		return errors.New("telegram not configured")
	}
	var errs []string
	for _, chat := range n.tg.ChatIDs {
		body, _ := json.Marshal(map[string]any{"chat_id": chat, "text": msg, "disable_web_page_preview": true})
		req, _ := http.NewRequestWithContext(ctx, "POST", "https://api.telegram.org/bot"+n.tg.BotToken+"/sendMessage", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := n.http.Do(req)
		if err != nil {
			// the URL contains the token; never surface it
			errs = append(errs, chat+": request failed")
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		resp.Body.Close()
		var r struct {
			OK          bool   `json:"ok"`
			Description string `json:"description"`
		}
		json.Unmarshal(b, &r)
		if !r.OK {
			errs = append(errs, fmt.Sprintf("%s: %s", chat, r.Description))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
