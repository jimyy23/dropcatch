// Package config loads process configuration from the environment.
// All credentials live here (from .env), never in the database.
package config

import (
	"os"
	"strings"
)

// Contact is the registrant contact used by registrars that need one inline.
type Contact struct {
	FirstName, LastName, Organization string
	Email, Phone                      string // phone in +CC.NUMBER form, e.g. +1.5555555555
	Street, Street2, City, State      string
	PostalCode, Country               string // ISO 3166-1 alpha-2
}

func (c Contact) Complete() bool {
	return c.FirstName != "" && c.LastName != "" && c.Email != "" && c.Phone != "" && c.Street != "" && c.City != "" && c.PostalCode != "" && c.Country != ""
}

type Dynadot struct {
	APIKey, APISecret string
	Sandbox           bool
	ContactID         string // registrant/admin/tech/billing contact id; empty = inline contact
	Privacy           string // off | partial | full
	Currency          string
}

type Porkbun struct {
	APIKey, SecretKey string
	WhoisPrivacy      bool
}

type InternetBS struct {
	APIKey, Password  string
	Test              bool
	CloneContactsFrom string // CloneContactsFromDomain
	PrivateWhois      string // FULL | PARTIAL | DISABLE
}

type Netim struct {
	ID, Password                     string
	OTE                              bool
	OwnerID, AdminID, TechID, BillID string
	Nameservers                      []string
}

type Regery struct {
	APIKey, APISecret string
	ContactID         string   // existing contact id; empty = saved from REGISTRANT_*
	Nameservers       []string // empty = Regery default nameservers ("basic")
	Services          []string // optional contact services, e.g. proxy
}

type NameSilo struct {
	APIKey      string
	ContactID   string   // contact profile id; empty = REGISTRANT_* inline, else the account default profile
	Private     bool     // WHOIS privacy
	Nameservers []string // empty = NameSilo defaults
}

type Cloudflare struct {
	APIToken, AccountID string
}

type Twilio struct {
	AccountSID, AuthToken, From string
	To                          []string
}

type Telegram struct {
	BotToken string
	ChatIDs  []string
}

// Env is process-level configuration.
type Env struct {
	Listen        string
	DBPath        string
	BaseURL       string
	SecureCookies bool
	TrustProxy    bool
	AdminUser     string
	AdminPassword string
	LogLevel      string

	WhoisURL      string
	WhoisPassword string

	// OrdersDryRun never places real orders (Porkbun uses its dryRun API,
	// other registrars are simulated). Use it to rehearse a drop.
	OrdersDryRun bool

	Contact    Contact
	Dynadot    Dynadot
	Porkbun    Porkbun
	InternetBS InternetBS
	Netim      Netim
	Regery     Regery
	NameSilo   NameSilo
	Cloudflare Cloudflare
	Twilio     Twilio
	Telegram   Telegram
}

func get(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func getBool(k string, def bool) bool {
	switch strings.ToLower(get(k, "")) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

func list(k string) []string {
	var out []string
	for _, p := range strings.Split(get(k, ""), ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Load reads configuration from environment variables.
func Load() Env {
	base := strings.TrimRight(get("BASE_URL", ""), "/")
	netimID := get("NETIM_ID", "")
	return Env{
		Listen:        get("LISTEN_ADDR", ":8080"),
		DBPath:        get("DB_PATH", "./data/dropcatch.db"),
		BaseURL:       base,
		SecureCookies: getBool("SECURE_COOKIES", strings.HasPrefix(base, "https://")),
		TrustProxy:    getBool("TRUST_PROXY", false),
		AdminUser:     get("ADMIN_USERNAME", ""),
		AdminPassword: get("ADMIN_PASSWORD", ""),
		LogLevel:      get("LOG_LEVEL", "info"),
		WhoisURL:      get("WHOIS_URL", ""),
		WhoisPassword: get("WHOIS_PASSWORD", ""),
		OrdersDryRun:  getBool("ORDERS_DRY_RUN", false),
		Contact: Contact{
			FirstName: get("REGISTRANT_FIRST_NAME", ""), LastName: get("REGISTRANT_LAST_NAME", ""),
			Organization: get("REGISTRANT_ORGANIZATION", ""), Email: get("REGISTRANT_EMAIL", ""),
			Phone: get("REGISTRANT_PHONE", ""), Street: get("REGISTRANT_STREET", ""), Street2: get("REGISTRANT_STREET2", ""),
			City: get("REGISTRANT_CITY", ""), State: get("REGISTRANT_STATE", ""),
			PostalCode: get("REGISTRANT_POSTAL_CODE", ""), Country: strings.ToUpper(get("REGISTRANT_COUNTRY", "")),
		},
		Dynadot: Dynadot{
			APIKey: get("DYNADOT_API_KEY", ""), APISecret: get("DYNADOT_API_SECRET", ""),
			Sandbox: getBool("DYNADOT_SANDBOX", false), ContactID: get("DYNADOT_CONTACT_ID", ""),
			Privacy: get("DYNADOT_PRIVACY", "full"), Currency: strings.ToLower(get("DYNADOT_CURRENCY", "usd")),
		},
		Porkbun: Porkbun{
			APIKey: get("PORKBUN_API_KEY", ""), SecretKey: get("PORKBUN_SECRET_API_KEY", ""),
			WhoisPrivacy: getBool("PORKBUN_WHOIS_PRIVACY", true),
		},
		InternetBS: InternetBS{
			APIKey: get("INTERNETBS_API_KEY", ""), Password: get("INTERNETBS_PASSWORD", ""),
			Test: getBool("INTERNETBS_TEST", false), CloneContactsFrom: get("INTERNETBS_CLONE_CONTACTS_FROM", ""),
			PrivateWhois: strings.ToUpper(get("INTERNETBS_PRIVATE_WHOIS", "")),
		},
		Netim: Netim{
			ID: netimID, Password: get("NETIM_PASSWORD", ""), OTE: getBool("NETIM_OTE", false),
			OwnerID: get("NETIM_OWNER_ID", ""), AdminID: get("NETIM_ADMIN_ID", netimID),
			TechID: get("NETIM_TECH_ID", netimID), BillID: get("NETIM_BILLING_ID", netimID),
			Nameservers: list("NETIM_NAMESERVERS"),
		},
		Regery: Regery{
			APIKey: get("REGERY_API_KEY", ""), APISecret: get("REGERY_API_SECRET", ""),
			ContactID: get("REGERY_CONTACT_ID", ""), Nameservers: list("REGERY_NAMESERVERS"), Services: list("REGERY_SERVICES"),
		},
		NameSilo: NameSilo{
			APIKey: get("NAMESILO_API_KEY", ""), ContactID: get("NAMESILO_CONTACT_ID", ""),
			Private: getBool("NAMESILO_PRIVATE", true), Nameservers: list("NAMESILO_NAMESERVERS"),
		},
		Cloudflare: Cloudflare{APIToken: get("CLOUDFLARE_API_TOKEN", ""), AccountID: get("CLOUDFLARE_ACCOUNT_ID", "")},
		Twilio: Twilio{
			AccountSID: get("TWILIO_ACCOUNT_SID", ""), AuthToken: get("TWILIO_AUTH_TOKEN", ""),
			From: get("TWILIO_FROM", ""), To: list("TWILIO_TO"),
		},
		Telegram: Telegram{BotToken: get("TELEGRAM_BOT_TOKEN", ""), ChatIDs: list("TELEGRAM_CHAT_IDS")},
	}
}
