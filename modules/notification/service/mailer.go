// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"context"
	"fmt"
	"net"
	"net/smtp"
	"time"
)

// defaultSMTPTimeout bounds both the dial and the whole SMTP conversation: net/smtp.SendMail has
// no timeout of its own — a hung dial to a dead/firewalled SMTP host blocks the calling goroutine
// forever, which in this worker is one job's delivery goroutine, not the whole process, but still
// needs a bound so a stuck job doesn't sit leased forever.
const defaultSMTPTimeout = 10 * time.Second

// Mailer delivers a job via net/smtp to a mailpit container (dev), never a vendor SDK. No auth
// (mailpit accepts anonymous SMTP on 1025 by default).
type Mailer struct {
	Host string
	Port string
	From string
	// Timeout bounds the dial + the SMTP conversation. Zero uses defaultSMTPTimeout.
	Timeout time.Duration
}

func NewMailer(host, port, from string) *Mailer {
	return &Mailer{Host: host, Port: port, From: from, Timeout: defaultSMTPTimeout}
}

// buildMessage renders the raw RFC 5322 message Deliver sends, split out so the Message-Id
// header is unit-testable without a real SMTP conversation. Message-Id is keyed on the delivery
// job's own id — stable across retries and crash-reclaims (same job row, same id), the SMTP-side
// equivalent of webhook.go's X-Kiban-Delivery-Id — so a receiving mail system can dedupe a
// redelivery of the same job against a copy it already processed (delivery is at-least-once,
// never exactly-once — this header is what makes dedupe possible).
func (m *Mailer) buildMessage(d JobDelivery) string {
	to := d.Job.Target
	messageID := fmt.Sprintf("<%s@kiban.notification>", d.Job.ID.String())
	return fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMessage-Id: %s\r\n\r\n%s\r\n", m.From, to, d.SubjectLine, messageID, d.Body)
}

// Deliver dials with a context deadline (net/smtp.SendMail cannot time out on its own — it has no
// context parameter and no dial-timeout option — so this reimplements SendMail's steps by hand:
// dial via (&net.Dialer{}).DialContext against a deadline, then feed the resulting conn to
// smtp.NewClient, matching every other step SendMail itself performs).
func (m *Mailer) Deliver(ctx context.Context, d JobDelivery) error {
	addr := net.JoinHostPort(m.Host, m.Port)
	to := d.Job.Target
	msg := m.buildMessage(d)

	timeout := m.Timeout
	if timeout <= 0 {
		timeout = defaultSMTPTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("notification: smtp dial %s: %w", addr, err)
	}
	// The dial's own deadline only bounds connection establishment; net.Conn.SetDeadline bounds
	// the rest of the SMTP conversation (HELO/MAIL/RCPT/DATA) that follows on the same conn,
	// since smtp.Client has no context support past NewClient either.
	if deadline, ok := dialCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	client, err := smtp.NewClient(conn, m.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("notification: smtp client %s: %w", addr, err)
	}
	defer func() { _ = client.Close() }()

	if err := client.Mail(m.From); err != nil {
		return fmt.Errorf("notification: smtp MAIL FROM %s: %w", addr, err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("notification: smtp RCPT TO %s: %w", addr, err)
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("notification: smtp DATA %s: %w", addr, err)
	}
	if _, err := wc.Write([]byte(msg)); err != nil {
		return fmt.Errorf("notification: smtp write body %s: %w", addr, err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("notification: smtp close body %s: %w", addr, err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("notification: smtp quit %s: %w", addr, err)
	}
	return nil
}
