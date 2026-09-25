// SPDX-License-Identifier: Apache-2.0

//go:build live

// The doc<->code drift pin, doc->code half: scrapes every real service's
// own `GET /metrics` on the isolated kiban-test compose stack (docker exec into each service's
// own container, matching internal/authz/harness/docker.go's established "shell out to docker"
// pattern for live-only tooling — these ports are deliberately compose-network-internal,
// so a host-run `go test` process has no other route to them) and asserts every metric name
// docs/metrics.md's table lists is observed in AT LEAST ONE of those scrapes.
// metrics_test.go's TestNames_MatchesDoc_BothDirections is this pin's other half (code->doc,
// build-tag-free, runs in `make check`): together they mean a metric can drift out of sync in
// neither direction without a red test — a name this package can register but the doc doesn't
// list, a doc row naming something this package never registers, or (this file) a doc row for
// something no running service ever actually emits a sample of.
//
// Run explicitly against a rebuilt, running kiban-test stack:
//
//	docker compose -p kiban-test --env-file .env.test -f infra/compose.yaml \
//	    -f infra/compose.test.yaml --project-directory infra up -d --build --wait
//	go test -tags live ./internal/obs/metrics/... -run TestLive -v
package metrics

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/livestack"
)

// liveScrapeTargets is every service that wires a Registry in, container name (the
// kiban-test compose project's own naming, `kiban-test-<service>-1`) plus the scheme+port its
// own /metrics answers on inside its own container (cmd/*/main.go's own listenPort constants).
// The GATEWAY is deliberately absent: it mounts no bare /metrics (its listener is the public
// edge); its exposition is scraped through the superadmin-guarded
// operator route instead, see scrapeGatewayViaOperatorRoute.
var liveScrapeTargets = []struct {
	container string
	url       string
}{
	{"kiban-test-registry-1", "http://127.0.0.1:8110/metrics"},
	{"kiban-test-identity-1", "http://127.0.0.1:8120/metrics"},
	{"kiban-test-org-1", "http://127.0.0.1:8130/metrics"},
	{"kiban-test-authz-1", "http://127.0.0.1:8140/metrics"},
	{"kiban-test-notification-1", "http://127.0.0.1:8150/metrics"},
	{"kiban-test-timesheet-1", "http://127.0.0.1:8160/metrics"},
	{"kiban-test-docs-1", "http://127.0.0.1:8170/metrics"},
	{"kiban-test-helpdesk-1", "http://127.0.0.1:8180/metrics"},
}

// scrape runs `docker exec <container> wget -qO- <url>` (wget ships in the alpine runtime-base
// image every service uses, infra/Dockerfile.service's own `apk add curl` sibling — curl is
// there too, but wget's plain stdout-on-success behavior needs no extra flags for either scheme).
func scrape(t *testing.T, container, url string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	args := []string{"exec", container, "wget", "-qO-"}
	if strings.HasPrefix(url, "https://") {
		args = append(args, "--no-check-certificate")
	}
	args = append(args, url)
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec %s wget %s: %v\n%s", container, url, err, string(out))
	}
	return string(out)
}

// scrapedMetricNames parses Prometheus text-exposition output, returning every distinct metric
// FAMILY name observed — read from each family's own "# TYPE <name> <type>" comment line, never
// from a sample line directly: a histogram's actual samples are named "<family>_bucket"/
// "<family>_sum"/"<family>_count" (never the bare family name itself), so parsing sample lines
// would never match a doc row like "http_request_duration_seconds" at all. The TYPE line is
// exactly the client library's own declaration of the family's base name, emitted once per
// family that has at least one sample (client_golang omits a family with zero samples entirely
// — same reason a family with genuinely no traffic yet must not appear here, which is correct).
func scrapedMetricNames(body string) map[string]bool {
	names := map[string]bool{}
	typeLineRe := regexp.MustCompile(`^# TYPE ([a-zA-Z_:][a-zA-Z0-9_:]*) `)
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		m := typeLineRe.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		names[m[1]] = true
	}
	return names
}

// TestLiveMetrics_EveryDocMetricIsObservedSomewhere scrapes every service in liveScrapeTargets
// and asserts every name docs/metrics.md's table lists appears in the UNION of all
// scrapes — never requiring a single service to emit every name (most families are
// service-specific by design; see the doc's own per-family tables). Several families are
// counters/histograms that Prometheus's client library omits entirely from a scrape until at
// least one sample has been recorded (kiban_authz_decisions_total, kiban_gateway_upstream_*,
// kiban_delivery_attempts_total) — a fresh kiban-test stack that has never actually served any
// end-user request wouldn't have any. generateLiveTraffic drives exactly enough real traffic
// (one real login + one effective-access decision + one module-proxy call + one delivery job
// left for the running worker container to pick up) to make every family observable, rather
// than this test silently passing vacuously on families nothing has ever populated.
func TestLiveMetrics_EveryDocMetricIsObservedSomewhere(t *testing.T) {
	doc := docMetricNames(t)
	mintSuperadminBearer := generateLiveTraffic(t)
	gwBase := "https://127.0.0.1:" + liveTestEnv(t, "KIBAN_GATEWAY_TLS_HOST_PORT")

	// The delivery job (email) and the just-completed decision/proxy calls may take a moment to
	// land in a scrape (worker poll interval, request/metrics-write ordering) — poll briefly
	// rather than scrape exactly once.
	deadline := time.Now().Add(20 * time.Second)
	var missing []string
	for {
		observed := map[string]bool{}
		for _, target := range liveScrapeTargets {
			body := scrape(t, target.container, target.url)
			for name := range scrapedMetricNames(body) {
				observed[name] = true
			}
		}
		for name := range scrapedMetricNames(scrapeGatewayViaOperatorRoute(t, gwBase, mintSuperadminBearer())) {
			observed[name] = true
		}
		missing = missing[:0]
		for _, name := range doc {
			if !observed[name] {
				missing = append(missing, name)
			}
		}
		if len(missing) == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if len(missing) > 0 {
		t.Errorf("docs/metrics.md lists metrics never observed in any live kiban-test scrape: %v", missing)
	}
}

// TestLiveMetrics_OperatorRouteAggregatesEveryService proves the single-scrape-target model on the real
// compose topology: ONE GET /api/platform/metrics carries every foundation service's and every
// installed+enabled module's series under its `service` label, and a kiban_metrics_scrape_up=1
// per target (the gateway reached each one over the compose network — the spec's stop
// condition, checked here rather than assumed).
func TestLiveMetrics_OperatorRouteAggregatesEveryService(t *testing.T) {
	mintSuperadminBearer := generateLiveTraffic(t)
	gwBase := "https://127.0.0.1:" + liveTestEnv(t, "KIBAN_GATEWAY_TLS_HOST_PORT")
	body := scrapeGatewayViaOperatorRoute(t, gwBase, mintSuperadminBearer())

	expected := []string{"gateway"}
	for _, target := range liveScrapeTargets {
		expected = append(expected, strings.TrimSuffix(strings.TrimPrefix(target.container, "kiban-test-"), "-1"))
	}
	for _, service := range expected {
		if !strings.Contains(body, `kiban_metrics_scrape_up{service="`+service+`"} 1`+"\n") {
			t.Errorf("aggregate lacks kiban_metrics_scrape_up{service=%q} 1", service)
		}
	}
	for _, line := range []string{
		`kiban_build_info{commit=`, // every service stamps one; two spot checks by label below
		`service="registry"`, `service="notification"`,
	} {
		if !strings.Contains(body, line) {
			t.Errorf("aggregate lacks %q", line)
		}
	}
	if t.Failed() {
		t.Logf("aggregate body (first 3000 bytes):\n%s", truncateLive(body, 3000))
	}
}

// liveTestEnv reads .env.test (this live proof deliberately targets kiban-test, not
// .env's own live stack), process environment taking priority.
func liveTestEnv(t *testing.T, name string) string { return livestack.TestStackEnv(t, name) }

// generateLiveTraffic drives exactly enough real end-to-end activity against the running
// kiban-test stack to populate every counter/histogram family the Registry can register,
// so TestLiveMetrics_EveryDocMetricIsObservedSomewhere never passes vacuously on a family nothing
// has ever recorded a sample for:
//
//  1. A real interactive OIDC/PKCE login (a throwaway Keycloak user, same technique
//     internal/bootstrap/browser_login_live_test.go's own TestBrowserLogin_
//     InteractiveFlowIssuesAuthorizationCode established for this exact purpose — duplicated
//     here rather than imported, since that helper is unexported and internal/bootstrap is not a
//     dependency this package should otherwise need) yields a real kiban-api-audience bearer.
//  2. That bearer drives one real POST /api/auth/effective-access/can through the gateway
//     (populates kiban_authz_decisions_total/kiban_authz_decision_duration_seconds on authz) and
//     one GET /api/notification/... module-proxy call (populates
//     kiban_gateway_upstream_requests_total/duration_seconds on the gateway — the call reaching
//     notification at all, regardless of what notification itself answers, is what the gateway's
//     own upstream metric measures).
//  3. A delivery_job row is inserted directly (kiban_notification role, claim_group='default' —
//     DELIBERATELY the live compose container's own worker claim group, not a test-isolated one;
//     every other package's own live test uses a random per-run claim_group specifically to
//     avoid the running container's worker, see modules/notification/service/dbtest_env_test.go's
//     own comment — this is the one deliberate exception, because the whole point here is for
//     that real running worker to claim and attempt it, populating kiban_delivery_attempts_total
//     on notification's own /metrics).
func generateLiveTraffic(t *testing.T) (mintSuperadminBearer func() string) {
	t.Helper()
	// This func creates a Keycloak user and inserts DB rows — never against the
	// PUBLIC deployment (same guard every other mutating live test in this repo checks first).
	if livestack.TargetsLiveStack() {
		t.Fatal(livestack.RefusalMessage)
	}

	kcBase := "http://127.0.0.1:" + liveTestEnv(t, "KEYCLOAK_HOST_PORT")
	realm := liveTestEnv(t, "KEYCLOAK_REALM")
	adminUser := liveTestEnv(t, "KC_BOOTSTRAP_ADMIN_USERNAME")
	adminPass := liveTestEnv(t, "KC_BOOTSTRAP_ADMIN_PASSWORD")
	gwBase := "https://127.0.0.1:" + liveTestEnv(t, "KIBAN_GATEWAY_TLS_HOST_PORT")

	httpClient := &http.Client{Timeout: 10 * time.Second}
	adminToken, err := kcAdminToken(httpClient, kcBase, adminUser, adminPass)
	if err != nil {
		t.Fatalf("generateLiveTraffic: obtain Keycloak master admin token: %v", err)
	}

	username := "kiban-metrics-live"
	password := "metrics-live-" + randString(t, 20)
	if err := kcEnsureTestUser(httpClient, kcBase, realm, adminToken, username, password); err != nil {
		t.Fatalf("generateLiveTraffic: ensure throwaway login user: %v", err)
	}

	bearer, err := interactiveLogin(t, gwBase, realm, username, password)
	if err != nil {
		t.Fatalf("generateLiveTraffic: interactive login: %v", err)
	}

	tlsClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	// One real authz decision (whatever the outcome — ALLOWED or a denial reason, both are valid
	// samples of kiban_authz_decisions_total{reason}).
	canBody, _ := json.Marshal(map[string]any{"featureKey": "notification.access", "scope": "global"})
	canReq, _ := http.NewRequest(http.MethodPost, gwBase+"/api/auth/effective-access/can", bytes.NewReader(canBody))
	canReq.Header.Set("Authorization", "Bearer "+bearer)
	canReq.Header.Set("Content-Type", "application/json")
	if resp, err := tlsClient.Do(canReq); err != nil {
		t.Logf("generateLiveTraffic: POST /api/auth/effective-access/can: %v (non-fatal — best-effort traffic generation)", err)
	} else {
		resp.Body.Close()
	}

	// platform.module_catalog/module_installation are shared tables on the kiban-test stack;
	// fixtures that truncate them reseed the built-in modules on cleanup, so this is a check,
	// not a repair.
	ensureModuleInstalled(t, "notification")

	// One real module-proxy call (whatever notification itself answers — even a 403/404 from
	// notification is a real gateway_upstream sample; the request reaching the upstream at all
	// is what that metric measures, see this func's own doc comment).
	proxyReq, _ := http.NewRequest(http.MethodGet, gwBase+"/api/notification/v1/companies/"+uuid.NewString()+"/channels", nil)
	proxyReq.Header.Set("Authorization", "Bearer "+bearer)
	if resp, err := tlsClient.Do(proxyReq); err != nil {
		t.Logf("generateLiveTraffic: GET /api/notification/.../channels: %v (non-fatal — best-effort traffic generation)", err)
	} else {
		resp.Body.Close()
	}

	if err := seedDeliveryJobForLiveWorker(t); err != nil {
		t.Logf("generateLiveTraffic: seed delivery job: %v (non-fatal — best-effort traffic generation)", err)
	}
	// The operator route that serves the gateway's own metrics is superadmin guarded, so the
	// scrape needs the REAL seeded superadmin. Same recipe as internal/gateway/
	// platform_openapi_live_test.go: kiban-test realm only, reset its password for this run
	// (it is the throwaway test realm — livestack guard above forbids the public one).
	suUser := liveTestEnv(t, "KIBAN_SUPERADMIN_USERNAME")
	suPass := "metrics-su-" + randString(t, 20)
	if err := kcEnsureTestUser(httpClient, kcBase, realm, adminToken, suUser, suPass); err != nil {
		t.Fatalf("generateLiveTraffic: reset superadmin password on kiban-test realm: %v", err)
	}
	// The shared kiban-test DB's package fixtures TRUNCATE identity.user_account, so the
	// superadmin's identity row may be gone by the time this test runs inside `make
	// coverage-gate`. Converge it and the superadmin tuple idempotently — the e2e-shared
	// convergeSuperadminIdentity recipe ported to Go.
	if err := convergeSuperadminRole(t, kcSub(t, httpClient, kcBase, realm, adminToken, suUser), suUser); err != nil {
		t.Fatalf("generateLiveTraffic: converge superadmin: %v", err)
	}
	// Return a MINTER, not a token: the kiban-test realm's access-token lifetime can be very
	// short (the session-expiry e2e lowers it on the kiban-frontend client), so each scrape
	// mints a fresh bearer immediately before use rather than trusting one minted up front.
	return func() string {
		b, err := interactiveLogin(t, gwBase, realm, suUser, suPass)
		if err != nil {
			t.Fatalf("superadmin interactive login: %v", err)
		}
		return b
	}

}

func randString(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

// kcAdminToken obtains a master-realm admin access token (password grant, client_id admin-cli —
// the same credential/mechanism internal/bootstrap/kcmaster.go's own kcMasterClient.token uses).
func kcAdminToken(httpClient *http.Client, kcBase, username, password string) (string, error) {
	form := url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {username}, "password": {password}}
	req, err := http.NewRequest(http.MethodPost, kcBase+"/realms/master/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("no access_token in response")
	}
	return out.AccessToken, nil
}

// kcEnsureTestUser creates (or resets) a throwaway user with a real, non-temporary password and
// no requiredActions (no MFA-setup prompt) — same shape as internal/bootstrap/
// browser_login_live_test.go's own browserLoginTestUser, idempotent so re-running this test
// against the same stack never fails on a duplicate-user conflict.
func kcEnsureTestUser(httpClient *http.Client, kcBase, realm, adminToken, username, password string) error {
	adminBase := kcBase + "/admin/realms/" + realm

	req, _ := http.NewRequest(http.MethodGet, adminBase+"/users?username="+url.QueryEscape(username)+"&exact=true", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("find user: %w", err)
	}
	var found []struct {
		ID string `json:"id"`
	}
	err = json.NewDecoder(resp.Body).Decode(&found)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("decode find-user response: %w", err)
	}

	credential := map[string]any{"type": "password", "value": password, "temporary": false}

	if len(found) == 0 {
		body, _ := json.Marshal(map[string]any{
			"username": username, "email": username + "@example.invalid", "enabled": true, "emailVerified": true,
			"firstName": "Kiban", "lastName": "Metrics Live",
			"requiredActions": []string{},
			"credentials":     []any{credential},
		})
		req, _ = http.NewRequest(http.MethodPost, adminBase+"/users", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("create user: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("create user: HTTP %d: %s", resp.StatusCode, string(b))
		}
		return nil
	}

	id := found[0].ID
	body, _ := json.Marshal(map[string]any{"requiredActions": []string{}, "enabled": true})
	req, _ = http.NewRequest(http.MethodPut, adminBase+"/users/"+id, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	if resp, err := httpClient.Do(req); err != nil {
		return fmt.Errorf("reset requiredActions: %w", err)
	} else {
		resp.Body.Close()
	}

	credBody, _ := json.Marshal(credential)
	req, _ = http.NewRequest(http.MethodPut, adminBase+"/users/"+id+"/reset-password", bytes.NewReader(credBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	resp2, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("reset password: %w", err)
	}
	defer resp2.Body.Close()
	return nil
}

var loginFormActionRe = regexp.MustCompile(`(?is)<form[^>]*id="kc-form-login"[^>]*action="([^"]*)"`)

// interactiveLogin drives the real interactive OIDC/PKCE authorization-code flow through the
// gateway's /auth/* proxy (same technique, same reason, as internal/bootstrap/
// browser_login_live_test.go's TestBrowserLogin_InteractiveFlowIssuesAuthorizationCode — a
// cookie-jar http.Client walking the real Keycloak login form) and exchanges the resulting code
// for a real kiban-api-audience access token.
func interactiveLogin(t *testing.T, gwBase, realm, username, password string) (string, error) {
	t.Helper()
	redirectURI := "http://localhost:5173/callback"
	verifierBytes := make([]byte, 48)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := randString(t, 16)

	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{
		Jar:       jar,
		Timeout:   20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	authURL := fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/auth?%s", gwBase, realm, url.Values{
		"client_id": {"kiban-frontend"}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"scope": {"openid"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {state},
	}.Encode())

	resp, err := client.Get(authURL)
	if err != nil {
		return "", fmt.Errorf("GET authorize endpoint: %w", err)
	}
	loginHTML, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("read login page: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET authorize endpoint = HTTP %d: %s", resp.StatusCode, truncateLive(string(loginHTML), 1000))
	}
	m := loginFormActionRe.FindStringSubmatch(string(loginHTML))
	if m == nil {
		return "", fmt.Errorf("no <form id=\"kc-form-login\"> action found in login page: %s", truncateLive(string(loginHTML), 1000))
	}
	formAction := strings.ReplaceAll(m[1], "&amp;", "&")

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	loginResp, err := client.PostForm(formAction, url.Values{"username": {username}, "password": {password}, "credentialId": {""}})
	if err != nil {
		return "", fmt.Errorf("POST login form: %w", err)
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusFound && loginResp.StatusCode != http.StatusSeeOther {
		b, _ := io.ReadAll(loginResp.Body)
		return "", fmt.Errorf("POST login form = HTTP %d, want a redirect; body: %s", loginResp.StatusCode, truncateLive(string(b), 1000))
	}
	location := loginResp.Header.Get("Location")
	locURL, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("parse redirect Location %q: %w", location, err)
	}
	code := locURL.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("final redirect %q carries no code param", location)
	}

	tokenForm := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
		"client_id": {"kiban-frontend"}, "code_verifier": {verifier},
	}
	tokenResp, err := client.PostForm(fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/token", gwBase, realm), tokenForm)
	if err != nil {
		return "", fmt.Errorf("exchange code for token: %w", err)
	}
	defer tokenResp.Body.Close()
	var tokenOut struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenOut); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if tokenOut.AccessToken == "" {
		return "", fmt.Errorf("token exchange returned no access_token")
	}
	return tokenOut.AccessToken, nil
}

func truncateLive(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "... (truncated)"
}

// ensureModuleInstalled fails fast when moduleKey is not installed+enabled on the kiban-test
// registry, so the module-proxy call below cannot silently measure a MODULE_NOT_INSTALLED
// answer instead of an upstream request.
func ensureModuleInstalled(t *testing.T, moduleKey string) {
	t.Helper()
	if livestack.TargetsLiveStack() {
		t.Fatal(livestack.RefusalMessage)
	}

	dsn := fmt.Sprintf(
		"postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		"kiban", liveTestEnv(t, "KIBAN_DB_PASSWORD"),
		liveTestEnv(t, "POSTGRES_HOST_PORT"), liveTestEnv(t, "POSTGRES_DB"),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("ensureModuleInstalled: connect: %v", err)
	}
	defer pool.Close()

	installed := func() bool {
		var count int
		qctx, qcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer qcancel()
		if err := pool.QueryRow(qctx, `SELECT count(*) FROM platform.module_installation WHERE module_key = $1 AND installed AND enabled`, moduleKey).Scan(&count); err != nil {
			t.Fatalf("ensureModuleInstalled: query module_installation: %v", err)
		}
		return count > 0
	}
	if !installed() {
		t.Fatalf("ensureModuleInstalled: %s is not installed+enabled on the kiban-test registry — did KIBAN_INSTALLED_MODULES change, or is the registry container unhealthy?", moduleKey)
	}
}

// seedDeliveryJobForLiveWorker inserts one real channel+message+delivery_job row directly
// (kiban_notification DB role, claim_group='default') — see generateLiveTraffic's own doc
// comment for why 'default' (the live worker container's own claim group) is the deliberate
// exception here. The job's target address doesn't need to be deliverable: whether the running
// worker's SMTP attempt against mailpit succeeds or fails, either outcome increments
// kiban_delivery_attempts_total{kind="email",outcome=...} — this seed only needs the worker to
// ATTEMPT it, not necessarily succeed.
func seedDeliveryJobForLiveWorker(t *testing.T) error {
	t.Helper()
	dsn := fmt.Sprintf(
		"postgres://kiban_notification:%s@127.0.0.1:%s/%s?sslmode=disable",
		liveTestEnv(t, "KIBAN_NOTIFICATION_DB_PASSWORD"), liveTestEnv(t, "POSTGRES_HOST_PORT"), liveTestEnv(t, "POSTGRES_DB"),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	companyID := uuid.NewString()
	channelKey := "live-metrics-proof"
	var channelID string
	err = pool.QueryRow(ctx, `
		INSERT INTO notification.channel (company_id, key, label, kind)
		VALUES ($1, $2, 'Live Metrics Proof', 'email') RETURNING id`,
		companyID, channelKey,
	).Scan(&channelID)
	if err != nil {
		return fmt.Errorf("insert channel: %w", err)
	}

	var messageID string
	err = pool.QueryRow(ctx, `
		INSERT INTO notification.message (company_id, channel_id, subject_line, body, created_by)
		VALUES ($1, $2, 'live metrics proof', 'live metrics proof body', 'metrics-live-test')
		RETURNING id`,
		companyID, channelID,
	).Scan(&messageID)
	if err != nil {
		return fmt.Errorf("insert message: %w", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO notification.delivery_job (message_id, kind, target, claim_group)
		VALUES ($1, 'email', $2, 'default')`,
		messageID, "metrics-live-"+randString(t, 8)+"@example.invalid",
	); err != nil {
		return fmt.Errorf("insert delivery_job: %w", err)
	}
	return nil
}

// scrapeGatewayViaOperatorRoute fetches the gateway's OWN exposition through the only place it is
// served: GET /api/platform/metrics behind RequireSuperadmin (the gateway has no bare
// /metrics — its listener is the public edge).
func scrapeGatewayViaOperatorRoute(t *testing.T, gwBase, superadminBearer string) string {
	t.Helper()
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	req, _ := http.NewRequest(http.MethodGet, gwBase+"/api/platform/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+superadminBearer)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /api/platform/metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /api/platform/metrics as superadmin: HTTP %d, want 200; body: %s; bearer-claims: %s", resp.StatusCode, truncateLive(string(b), 300), debugJWTClaims(superadminBearer))
	}
	var sb strings.Builder
	if _, err := io.Copy(&sb, resp.Body); err != nil {
		t.Fatalf("read /api/platform/metrics body: %v", err)
	}
	return sb.String()
}

// debugJWTClaims decodes (without verifying) a JWT payload for failure diagnostics only.
func debugJWTClaims(tok string) string {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return "<not a JWT>"
	}
	pad := parts[1]
	if m := len(pad) % 4; m != 0 {
		pad += strings.Repeat("=", 4-m)
	}
	b, err := base64.URLEncoding.DecodeString(pad)
	if err != nil {
		return "<undecodable: " + err.Error() + ">"
	}
	return truncateLive(string(b), 400)
}

// kcSub resolves a realm user's Keycloak id (== kc_sub) via the admin API.
func kcSub(t *testing.T, httpClient *http.Client, kcBase, realm, adminToken, username string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, kcBase+"/admin/realms/"+realm+"/users?username="+url.QueryEscape(username)+"&exact=true", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("kcSub: find user %q: %v", username, err)
	}
	defer resp.Body.Close()
	var found []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&found); err != nil || len(found) == 0 {
		t.Fatalf("kcSub: user %q not found in realm %q (decode err: %v)", username, realm, err)
	}
	return found[0].ID
}

// convergeSuperadminRole makes sure identity.user_account has a row for kcSub and that it holds
// the kiban-superadmin platform role — exactly the e2e-shared convergeSuperadminIdentity recipe
// (INSERT ... ON CONFLICT for the account; role + audit INSERT atomically, only when absent).
// Runs as the app-DB owner role (kiban) because the write spans identity + audit schemas,
// the same way the e2e fixture's psql does. kiban-test only (livestack guard already applied by
// the caller).
func convergeSuperadminRole(t *testing.T, kcSubID, username string) error {
	t.Helper()
	dsn := fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		"kiban", liveTestEnv(t, "KIBAN_DB_PASSWORD"),
		liveTestEnv(t, "POSTGRES_HOST_PORT"), liveTestEnv(t, "POSTGRES_DB"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	if _, err := pool.Exec(ctx, `
		INSERT INTO identity.user_account (kc_sub, email, preferred_username)
		VALUES ($1, NULL, $2)
		ON CONFLICT (kc_sub) DO UPDATE SET preferred_username = EXCLUDED.preferred_username, updated_at = now()`, kcSubID, username); err != nil {
		return fmt.Errorf("converge user_account: %w", err)
	}
	// The platform role's ONLY record is the authz tuple; its ledger and audit rows are written
	// only when the tuple is actually inserted (one statement — data-modifying CTEs — so they
	// commit together).
	if _, err := pool.Exec(ctx, `
		WITH ins AS (
			INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
			VALUES ('system', 'platform', 'superadmin', 'user', $1, '')
			ON CONFLICT DO NOTHING RETURNING subject_id
		), ledger AS (
			INSERT INTO authz.grant_ledger (actor, object_type, object_id, relation, subject_type, subject_id, subject_relation, op, correlation_id)
			SELECT 'bootstrap-e2e', 'system', 'platform', 'superadmin', 'user', subject_id, '', 'grant', 'metrics-live-convergence' FROM ins
		)
		INSERT INTO audit.authz__events (actor, action, subject, payload)
		SELECT 'bootstrap-e2e', 'authz.platform_role.grant', 'user:' || subject_id,
		       '{"role":"kiban-superadmin","grantedBy":"bootstrap-e2e","seed":"metrics-live-convergence"}'::jsonb
		FROM ins`, kcSubID); err != nil {
		return fmt.Errorf("converge superadmin tuple: %w", err)
	}
	return nil
}
