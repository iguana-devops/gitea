// Copyright 2019 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"net"
	"net/mail"
	"strings"
	"time"

	"code.gitea.io/gitea/modules/log"

	shellquote "github.com/kballard/go-shellquote"
)

// Mailer represents mail service.
type Mailer struct {
	// Mailer
	Name                 string `ini:"NAME"`
	From                 string `ini:"FROM"`
	EnvelopeFrom         string `ini:"ENVELOPE_FROM"`
	OverrideEnvelopeFrom bool   `ini:"-"`
	FromName             string `ini:"-"`
	FromEmail            string `ini:"-"`
	SendAsPlainText      bool   `ini:"SEND_AS_PLAIN_TEXT"`
	SubjectPrefix        string `ini:"SUBJECT_PREFIX"`

	// SMTP sender
	Protocol             string `ini:"PROTOCOL"`
	SMTPAddr             string `ini:"SMTP_ADDR"`
	SMTPPort             string `ini:"SMTP_PORT"`
	User                 string `ini:"USER"`
	Passwd               string `ini:"PASSWD"`
	EnableHelo           bool   `ini:"ENABLE_HELO"`
	HeloHostname         string `ini:"HELO_HOSTNAME"`
	ForceTrustServerCert bool   `ini:"FORCE_TRUST_SERVER_CERT"`
	UseClientCert        bool   `ini:"USE_CLIENT_CERT"`
	ClientCertFile       string `ini:"CLIENT_CERT_FILE"`
	ClientKeyFile        string `ini:"CLIENT_KEY_FILE"`

	// Sendmail sender
	SendmailPath        string        `ini:"SENDMAIL_PATH"`
	SendmailArgs        []string      `ini:"-"`
	SendmailTimeout     time.Duration `ini:"SENDMAIL_TIMEOUT"`
	SendmailConvertCRLF bool          `ini:"SENDMAIL_CONVERT_CRLF"`
}

// MailService the global mailer
var MailService *Mailer

func loadMailsFrom(rootCfg ConfigProvider) {
	loadMailerFrom(rootCfg)
	loadRegisterMailFrom(rootCfg)
	loadNotifyMailFrom(rootCfg)
	loadIncomingEmailFrom(rootCfg)
}

func loadMailerFrom(rootCfg ConfigProvider) {
	sec := rootCfg.Section("mailer")
	// Check mailer setting.
	if !sec.Key("ENABLED").MustBool() {
		return
	}

	// Handle Deprecations and map on to new configuration
	// DEPRECATED should not be removed because users maybe upgrade from lower version to the latest version
	// if these are removed, the warning will not be shown
	deprecatedSetting(rootCfg, "mailer", "MAILER_TYPE", "mailer", "PROTOCOL", "v1.19.0")
	if sec.HasKey("MAILER_TYPE") && !sec.HasKey("PROTOCOL") {
		if sec.Key("MAILER_TYPE").String() == "sendmail" {
			sec.Key("PROTOCOL").MustString("sendmail")
		}
	}

	deprecatedSetting(rootCfg, "mailer", "HOST", "mailer", "SMTP_ADDR", "v1.19.0")
	if sec.HasKey("HOST") && !sec.HasKey("SMTP_ADDR") {
		givenHost := sec.Key("HOST").String()
		addr, port, err := net.SplitHostPort(givenHost)
		if err != nil && strings.Contains(err.Error(), "missing port in address") {
			addr = givenHost
		} else if err != nil {
			log.Fatal("Invalid mailer.HOST (%s): %w", givenHost, err)
		}
		if addr == "" {
			addr = "127.0.0.1"
		}
		sec.Key("SMTP_ADDR").MustString(addr)
		sec.Key("SMTP_PORT").MustString(port)
	}

	deprecatedSetting(rootCfg, "mailer", "IS_TLS_ENABLED", "mailer", "PROTOCOL", "v1.19.0")
	if sec.HasKey("IS_TLS_ENABLED") && !sec.HasKey("PROTOCOL") {
		if sec.Key("IS_TLS_ENABLED").MustBool() {
			sec.Key("PROTOCOL").MustString("smtps")
		} else {
			sec.Key("PROTOCOL").MustString("smtp+starttls")
		}
	}

	deprecatedSetting(rootCfg, "mailer", "DISABLE_HELO", "mailer", "ENABLE_HELO", "v1.19.0")
	if sec.HasKey("DISABLE_HELO") && !sec.HasKey("ENABLE_HELO") {
		sec.Key("ENABLE_HELO").MustBool(!sec.Key("DISABLE_HELO").MustBool())
	}

	deprecatedSetting(rootCfg, "mailer", "SKIP_VERIFY", "mailer", "FORCE_TRUST_SERVER_CERT", "v1.19.0")
	if sec.HasKey("SKIP_VERIFY") && !sec.HasKey("FORCE_TRUST_SERVER_CERT") {
		sec.Key("FORCE_TRUST_SERVER_CERT").MustBool(sec.Key("SKIP_VERIFY").MustBool())
	}

	deprecatedSetting(rootCfg, "mailer", "USE_CERTIFICATE", "mailer", "USE_CLIENT_CERT", "v1.19.0")
	if sec.HasKey("USE_CERTIFICATE") && !sec.HasKey("USE_CLIENT_CERT") {
		sec.Key("USE_CLIENT_CERT").MustBool(sec.Key("USE_CERTIFICATE").MustBool())
	}

	deprecatedSetting(rootCfg, "mailer", "CERT_FILE", "mailer", "CLIENT_CERT_FILE", "v1.19.0")
	if sec.HasKey("CERT_FILE") && !sec.HasKey("CLIENT_CERT_FILE") {
		sec.Key("CERT_FILE").MustString(sec.Key("CERT_FILE").String())
	}

	deprecatedSetting(rootCfg, "mailer", "KEY_FILE", "mailer", "CLIENT_KEY_FILE", "v1.19.0")
	if sec.HasKey("KEY_FILE") && !sec.HasKey("CLIENT_KEY_FILE") {
		sec.Key("KEY_FILE").MustString(sec.Key("KEY_FILE").String())
	}

	deprecatedSetting(rootCfg, "mailer", "ENABLE_HTML_ALTERNATIVE", "mailer", "SEND_AS_PLAIN_TEXT", "v1.19.0")
	if sec.HasKey("ENABLE_HTML_ALTERNATIVE") && !sec.HasKey("SEND_AS_PLAIN_TEXT") {
		sec.Key("SEND_AS_PLAIN_TEXT").MustBool(!sec.Key("ENABLE_HTML_ALTERNATIVE").MustBool(false))
	}

	if sec.HasKey("PROTOCOL") && sec.Key("PROTOCOL").String() == "smtp+startls" {
		log.Error("Deprecated fallback `[mailer]` `PROTOCOL = smtp+startls` present. Use `[mailer]` `PROTOCOL = smtp+starttls`` instead. This fallback will be removed in v1.19.0")
		sec.Key("PROTOCOL").SetValue("smtp+starttls")
	}

	// Set default values & validate
	sec.Key("NAME").MustString(AppName)
	sec.Key("PROTOCOL").In("", []string{"smtp", "smtps", "smtp+starttls", "smtp+unix", "sendmail", "dummy"})
	sec.Key("ENABLE_HELO").MustBool(true)
	sec.Key("FORCE_TRUST_SERVER_CERT").MustBool(false)
	sec.Key("USE_CLIENT_CERT").MustBool(false)
	sec.Key("SENDMAIL_PATH").MustString("sendmail")
	sec.Key("SENDMAIL_TIMEOUT").MustDuration(5 * time.Minute)
	sec.Key("SENDMAIL_CONVERT_CRLF").MustBool(true)
	sec.Key("FROM").MustString(sec.Key("USER").String())

	// Now map the values on to the MailService
	MailService = &Mailer{}
	if err := sec.MapTo(MailService); err != nil {
		log.Fatal("Unable to map [mailer] section on to MailService. Error: %w", err)
	}

	// Infer SMTPPort if not set
	if MailService.SMTPPort == "" {
		switch MailService.Protocol {
		case "smtp":
			MailService.SMTPPort = "25"
		case "smtps":
			MailService.SMTPPort = "465"
		case "smtp+starttls":
			MailService.SMTPPort = "587"
		}
	}

	// Infer Protocol
	if MailService.Protocol == "" {
		if strings.ContainsAny(MailService.SMTPAddr, "/\\") {
			MailService.Protocol = "smtp+unix"
		} else {
			switch MailService.SMTPPort {
			case "25":
				MailService.Protocol = "smtp"
			case "465":
				MailService.Protocol = "smtps"
			case "587":
				MailService.Protocol = "smtp+starttls"
			default:
				log.Error("unable to infer unspecified mailer.PROTOCOL from mailer.SMTP_PORT = %q, assume using smtps", MailService.SMTPPort)
				MailService.Protocol = "smtps"
				if MailService.SMTPPort == "" {
					MailService.SMTPPort = "465"
				}
			}
		}
	}

	// we want to warn if users use SMTP on a non-local IP;
	// we might as well take the opportunity to check that it has an IP at all
	// This check is not needed for sendmail
	switch MailService.Protocol {
	case "sendmail":
		var err error
		MailService.SendmailArgs, err = shellquote.Split(sec.Key("SENDMAIL_ARGS").String())
		if err != nil {
			log.Error("Failed to parse Sendmail args: '%s' with error %w", sec.Key("SENDMAIL_ARGS").String(), err)
		}
	case "smtp", "smtps", "smtp+starttls", "smtp+unix":
		ips := tryResolveAddr(MailService.SMTPAddr)
		if MailService.Protocol == "smtp" {
			for _, ip := range ips {
				if !ip.IsLoopback() {
					log.Warn("connecting over insecure SMTP protocol to non-local address is not recommended")
					break
				}
			}
		}
	case "dummy": // just mention and do nothing
	}

	if MailService.From != "" {
		parsed, err := mail.ParseAddress(MailService.From)
		if err != nil {
			log.Fatal("Invalid mailer.FROM (%s): %w", MailService.From, err)
		}
		MailService.FromName = parsed.Name
		MailService.FromEmail = parsed.Address
	} else {
		log.Error("no mailer.FROM provided, email system may not work.")
	}

	switch MailService.EnvelopeFrom {
	case "":
		MailService.OverrideEnvelopeFrom = false
	case "<>":
		MailService.EnvelopeFrom = ""
		MailService.OverrideEnvelopeFrom = true
	default:
		parsed, err := mail.ParseAddress(MailService.EnvelopeFrom)
		if err != nil {
			log.Fatal("Invalid mailer.ENVELOPE_FROM (%s): %w", MailService.EnvelopeFrom, err)
		}
		MailService.OverrideEnvelopeFrom = true
		MailService.EnvelopeFrom = parsed.Address
	}

	log.Info("Mail Service Enabled")
}

func loadRegisterMailFrom(rootCfg ConfigProvider) {
	if !rootCfg.Section("service").Key("REGISTER_EMAIL_CONFIRM").MustBool() {
		return
	} else if MailService == nil {
		log.Warn("Register Mail Service: Mail Service is not enabled")
		return
	}
	Service.RegisterEmailConfirm = true
	log.Info("Register Mail Service Enabled")
}

func loadNotifyMailFrom(rootCfg ConfigProvider) {
	if !rootCfg.Section("service").Key("ENABLE_NOTIFY_MAIL").MustBool() {
		return
	} else if MailService == nil {
		log.Warn("Notify Mail Service: Mail Service is not enabled")
		return
	}
	Service.EnableNotifyMail = true
	log.Info("Notify Mail Service Enabled")
}

func tryResolveAddr(addr string) []net.IP {
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		addr = addr[1 : len(addr)-1]
	}
	ip := net.ParseIP(addr)
	if ip != nil {
		ips := make([]net.IP, 1)
		ips[0] = ip
		return ips
	}
	ips, err := net.LookupIP(addr)
	if err != nil {
		log.Warn("could not look up mailer.SMTP_ADDR: %w", err)
		return make([]net.IP, 0)
	}
	return ips
}
