// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	frontendClientID        = "kiban-frontend"
	apiClientID             = "kiban-api"
	identityServiceClientID = "kiban-identity-service"
	realmManagementClientID = "realm-management"
	browserFlowAlias        = "kiban browser"
	directGrantFlowAlias    = "kiban direct grant"
	builtinDirectGrantAlias = "direct grant"          // Keycloak's built-in flow the kiban one is copied from
	mfaAuthenticatorID      = "kiban-local-mfa-setup" // KibanLocalMfaSetupAuthenticatorFactory.PROVIDER_ID
	audienceMapperName      = "kiban-api-audience"

	// postLogoutRedirectURIsAttrKey is KC 26's separate client attribute governing RP-initiated
	// logout's post_logout_redirect_uri validation — distinct from `redirectUris`, which only
	// governs the AUTHORIZATION redirect. "+" is Keycloak's documented special value meaning
	// "same set as Valid Redirect URIs" — which already carries the dev-loopback/KIBAN_DOMAIN
	// origins (including the origin root the SDK's logout default targets) via the wildcarded
	// entries frontendOrigins() computes. Without this attribute set, KC shows an
	// "invalid redirect uri" error page on logout instead of completing it.
	postLogoutRedirectURIsAttrKey   = "post.logout.redirect.uris"
	postLogoutRedirectURIsAttrValue = "+"

	// serviceUID is the fixed uid every app service image runs as (infra/Dockerfile.service's
	// runtime-base; deploy/k8s pins the same via runAsUser) — the owner writeServiceSecrets
	// hands the identity client-secret file to.
	serviceUID = 65532
)

// identityServiceRoles is the EXACT realm-management client-role set the kiban-identity-service
// service account must hold — least privilege proven, not assumed. Any role beyond this set
// is a hard stop.
var identityServiceRoles = []string{"manage-users", "query-users", "view-users", "view-events"}

// RealmStep reconciles the Keycloak realm via the admin REST API: realm settings, the
// kiban-api/kiban-frontend clients, the MFA browser-flow wiring, the
// identity service-account client's exact realm-management roles, and per-service client
// secrets written to a shared volume as 0600 files.
type RealmStep struct{}

func (RealmStep) Name() string { return "realm" }

func (RealmStep) Run(ctx context.Context, deps *Deps) (Outcome, string, error) {
	if deps.KeycloakAdminBaseURL == "" {
		return OutcomeConverged, "realm: skipped (KeycloakAdminBaseURL not set)", nil
	}

	kc := newKCMasterClient(deps.HTTPClient, deps.KeycloakAdminBaseURL, deps.KeycloakRealm, deps.KCBootstrapAdminUsername, deps.KCBootstrapAdminPassword)

	var details []string
	applied := false

	// 1. Realm settings.
	changed, err := reconcileRealmSettings(ctx, kc)
	if err != nil {
		return OutcomeFailed, strings.Join(details, "; "), fmt.Errorf("realm: settings: %w", err)
	}
	applied = applied || changed
	details = append(details, fmt.Sprintf("settings: %s", outcomeWord(changed)))

	// 2. kiban-api (bearer-only).
	apiChanged, err := reconcileBearerOnlyClient(ctx, kc, apiClientID, "Kiban API")
	if err != nil {
		return OutcomeFailed, strings.Join(details, "; "), fmt.Errorf("realm: %s client: %w", apiClientID, err)
	}
	applied = applied || apiChanged
	details = append(details, fmt.Sprintf("client %s: %s", apiClientID, outcomeWord(apiChanged)))

	// 3. kiban-frontend (public, PKCE); redirect URIs from KIBAN_DOMAIN.
	feChanged, feInternalID, err := reconcileFrontendClient(ctx, kc, deps.KibanDomain)
	if err != nil {
		return OutcomeFailed, strings.Join(details, "; "), fmt.Errorf("realm: %s client: %w", frontendClientID, err)
	}
	applied = applied || feChanged
	details = append(details, fmt.Sprintf("client %s: %s", frontendClientID, outcomeWord(feChanged)))

	// 3b. Audience mapper: kiban-frontend tokens must carry aud=kiban-api (every service's
	// KEYCLOAK_AUDIENCE default) — a mapper targeting any other audience is a real bug this
	// step corrects, not cosmetic.
	mapperChanged, err := reconcileAudienceMapper(ctx, kc, feInternalID)
	if err != nil {
		return OutcomeFailed, strings.Join(details, "; "), fmt.Errorf("realm: audience mapper: %w", err)
	}
	applied = applied || mapperChanged
	details = append(details, fmt.Sprintf("audience mapper: %s", outcomeWord(mapperChanged)))

	// 3c. Service clients (KIBAN_SERVICE_CLIENTS): confidential clients with a service account
	// and the same kiban-api audience, so a backend can obtain a token by client credentials.
	for _, id := range deps.ServiceClients {
		scChanged, scInternalID, err := reconcileServiceClient(ctx, kc, id)
		if err != nil {
			return OutcomeFailed, strings.Join(details, "; "), fmt.Errorf("realm: service client %s: %w", id, err)
		}
		scMapperChanged, err := reconcileAudienceMapper(ctx, kc, scInternalID)
		if err != nil {
			return OutcomeFailed, strings.Join(details, "; "), fmt.Errorf("realm: service client %s audience mapper: %w", id, err)
		}
		applied = applied || scChanged || scMapperChanged
		details = append(details, fmt.Sprintf("service client %s: %s", id, outcomeWord(scChanged || scMapperChanged)))
	}

	// 4. MFA browser-flow wiring: realm's browserFlow must be browserFlowAlias, and that flow
	// must carry the MFA-setup authenticator as a REQUIRED step.
	if err := verifyMFAFlowWiring(ctx, kc); err != nil {
		return OutcomeFailed, strings.Join(details, "; "), fmt.Errorf("realm: MFA flow wiring: %w", err)
	}
	details = append(details, "MFA flow wiring: converged")

	// 4a. Direct-grant flow: the realm's directGrantFlow carries the same MFA-setup
	// authenticator, so a password grant (any client with direct access grants — admin-cli,
	// the proof scripts' throwaway clients, a leftover from a previous run) cannot mint a token
	// for a user whose required MFA credential is not yet enrolled: Keycloak refuses the grant
	// with "Account is not fully set up" instead of issuing it. Repaired in place (copy of the
	// built-in flow + the authenticator), so an existing realm converges without a re-import.
	dgChanged, err := reconcileDirectGrantFlow(ctx, kc)
	if err != nil {
		return OutcomeFailed, strings.Join(details, "; "), fmt.Errorf("realm: direct-grant MFA flow: %w", err)
	}
	applied = applied || dgChanged
	details = append(details, fmt.Sprintf("direct-grant MFA flow: %s", outcomeWord(dgChanged)))

	// 4b. User profile: Keycloak 24+'s declarative user profile SILENTLY DROPS attributes it
	// doesn't declare (unmanagedAttributePolicy defaults to disabled) on every admin user
	// update — identity's MFA sync reported success while kiban.login_security.* never
	// persisted, so no policy was ever enforced.
	// Declare both attributes as MANAGED with admin-only view/edit: the sync's writes stick,
	// and a user can never read or edit their own MFA requirement.
	upChanged, err := reconcileUserProfileAttributes(ctx, kc)
	if err != nil {
		return OutcomeFailed, strings.Join(details, "; "), fmt.Errorf("realm: user-profile MFA attributes: %w", err)
	}
	applied = applied || upChanged
	details = append(details, fmt.Sprintf("user-profile MFA attributes: %s", outcomeWord(upChanged)))

	// 5. Identity service account: EXACT realm-management role verification.
	roleDetail, err := verifyIdentityServiceRolesExact(ctx, kc)
	if err != nil {
		return OutcomeFailed, strings.Join(details, "; "), err
	}
	details = append(details, roleDetail)

	// 6. Per-service client secrets to the shared volume (0600).
	secretDetail, secretApplied, err := writeServiceSecrets(ctx, kc, deps)
	if err != nil {
		return OutcomeFailed, strings.Join(details, "; "), fmt.Errorf("realm: secrets: %w", err)
	}
	applied = applied || secretApplied
	details = append(details, secretDetail)

	if applied {
		return OutcomeApplied, strings.Join(details, "; "), nil
	}
	return OutcomeConverged, strings.Join(details, "; "), nil
}

func outcomeWord(changed bool) string {
	if changed {
		return "applied"
	}
	return "converged"
}

// realmSettings is the target state for the whitelisted realm fields this step manages —
// matching infra/keycloak-build/realm-kiban.json's own imported values where the import sets
// them; the brute-force and password-policy keys are applied on the first run against a fresh
// import and converge from then on.
var realmTargetSettings = map[string]any{
	// Brute-force protection: temporary lockout after 10 failures, 60s wait growing to 15 min,
	// failure counter window 12h, quick-login (two attempts under 1s) waits 60s.
	"bruteForceProtected":          true,
	"permanentLockout":             false,
	"failureFactor":                float64(10),
	"waitIncrementSeconds":         float64(60),
	"maxFailureWaitSeconds":        float64(900),
	"maxDeltaTimeSeconds":          float64(43200),
	"quickLoginCheckMilliSeconds":  float64(1000),
	"minimumQuickLoginWaitSeconds": float64(60),
	"passwordPolicy":               "length(12) and notUsername and notEmail",
	"displayName":                  "Kiban",
	"browserFlow":                  browserFlowAlias,
	"loginWithEmailAllowed":        true,
	"duplicateEmailsAllowed":       false,
	"registrationAllowed":          false,
	"rememberMe":                   true,
	"verifyEmail":                  true,
	"resetPasswordAllowed":         true,
	"eventsEnabled":                true,
	"adminEventsEnabled":           true,
	"adminEventsDetailsEnabled":    true,
	"eventsExpiration":             float64(7776000),
	"accessTokenLifespan":          float64(300),
	"ssoSessionIdleTimeout":        float64(1800),
	"ssoSessionMaxLifespan":        float64(36000),
}

// userProfileManagedAttributes are the MFA-policy attributes identity's sync writes
// (internal/identity/sync.go). Names must match sync.go's constants exactly.
var userProfileManagedAttributes = []string{
	"kiban.login_security.required_mode",
	"kiban.login_security.mfa",
}

// reconcileUserProfileAttributes declares userProfileManagedAttributes in the realm's user
// profile as managed, admin-only attributes (see RealmStep 4b's comment for why silence, not
// an error, is what happens without this). Idempotent: attributes already declared are left
// exactly as-is.
func reconcileUserProfileAttributes(ctx context.Context, kc *kcMasterClient) (bool, error) {
	var profile map[string]any
	if _, err := kc.do(ctx, http.MethodGet, "/users/profile", nil, &profile); err != nil {
		return false, fmt.Errorf("get user profile: %w", err)
	}
	attrs, _ := profile["attributes"].([]any)
	present := map[string]bool{}
	for _, a := range attrs {
		if m, ok := a.(map[string]any); ok {
			if n, ok := m["name"].(string); ok {
				present[n] = true
			}
		}
	}
	changed := false
	for _, name := range userProfileManagedAttributes {
		if present[name] {
			continue
		}
		attrs = append(attrs, map[string]any{
			"name": name,
			"permissions": map[string]any{
				"view": []string{"admin"},
				"edit": []string{"admin"},
			},
		})
		changed = true
	}
	if !changed {
		return false, nil
	}
	profile["attributes"] = attrs
	if _, err := kc.do(ctx, http.MethodPut, "/users/profile", profile, nil); err != nil {
		return false, fmt.Errorf("update user profile: %w", err)
	}
	return true, nil
}

func reconcileRealmSettings(ctx context.Context, kc *kcMasterClient) (bool, error) {
	current, err := kc.getRealm(ctx)
	if err != nil {
		return false, err
	}

	patch := map[string]any{}
	for k, want := range realmTargetSettings {
		if !equalRealmValue(current[k], want) {
			patch[k] = want
		}
	}
	if len(patch) == 0 {
		return false, nil
	}
	if err := kc.updateRealm(ctx, patch); err != nil {
		return false, err
	}
	return true, nil
}

// equalRealmValue compares a decoded-JSON current value (float64/bool/string via
// encoding/json's default map[string]any decoding) to a target value of the same Go kind.
func equalRealmValue(current, want any) bool {
	switch w := want.(type) {
	case bool:
		c, ok := current.(bool)
		return ok && c == w
	case float64:
		c, ok := current.(float64)
		return ok && c == w
	case string:
		c, ok := current.(string)
		return ok && c == w
	default:
		return false
	}
}

// reconcileBearerOnlyClient ensures a bearer-only client named wantID exists.
func reconcileBearerOnlyClient(ctx context.Context, kc *kcMasterClient, wantID, name string) (bool, error) {
	rep, found, err := kc.findClientByClientID(ctx, wantID)
	if err != nil {
		return false, err
	}
	if !found {
		_, err = kc.createClient(ctx, kcClientRep{
			ClientID: wantID, Name: name, Enabled: true, Protocol: "openid-connect", BearerOnly: true,
		})
		if err != nil {
			return false, fmt.Errorf("create %s: %w", wantID, err)
		}
		return true, nil
	}
	if !rep.BearerOnly || !rep.Enabled {
		rep.BearerOnly = true
		rep.Enabled = true
		if err := kc.updateClient(ctx, rep.ID, rep); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// frontendOrigins returns the redirect-URI/web-origin base(s) for kiban-frontend: KIBAN_DOMAIN
// when set (production), else the dev-loopback origins the imported realm already ships.
//
// The dev-loopback list must include every origin a real browser can complete the OIDC
// redirect FROM, not just the Vite dev-server origins: "https://127.0.0.1:8443" is the
// gateway's own TLS origin (`make dev`, where web/shell is served from via KIBAN_STATIC_DIR)
// and "https://127.0.0.1:18543" is the isolated test stack's gateway TLS origin
// (.env.test's KIBAN_GATEWAY_TLS_HOST_PORT). Missing either one makes Keycloak reject a
// browser login with "invalid redirect uri" — password-grant flows never exercise this because
// they never redirect back to the gateway's origin. Both are fixed literals rather than env
// vars: this branch is a fixed, enumerated dev/test-only allowlist, never reached once
// KIBAN_DOMAIN is set.
func frontendOrigins(kibanDomain string) (redirectURIs, webOrigins []string) {
	if kibanDomain == "" {
		return []string{
				"http://localhost:3000/*", "http://localhost:5173/*", "http://localhost/*",
				"https://127.0.0.1:8443/*", "https://127.0.0.1:18543/*",
			}, []string{
				"http://localhost:3000", "http://localhost:5173", "http://localhost",
				"https://127.0.0.1:8443", "https://127.0.0.1:18543",
			}
	}
	origin := "https://" + kibanDomain
	return []string{origin + "/*"}, []string{origin}
}

func reconcileFrontendClient(ctx context.Context, kc *kcMasterClient, kibanDomain string) (bool, string, error) {
	wantRedirects, wantOrigins := frontendOrigins(kibanDomain)

	rep, found, err := kc.findClientByClientID(ctx, frontendClientID)
	if !found {
		if err != nil {
			return false, "", err
		}
		id, err := kc.createClient(ctx, kcClientRep{
			ClientID: frontendClientID, Name: "Kiban Frontend", Enabled: true, Protocol: "openid-connect",
			PublicClient: true, StandardFlowEnabled: true, RedirectUris: wantRedirects, WebOrigins: wantOrigins,
			Attributes: map[string]string{
				"pkce.code.challenge.method":  "S256",
				postLogoutRedirectURIsAttrKey: postLogoutRedirectURIsAttrValue,
			},
		})
		if err != nil {
			return false, "", fmt.Errorf("create %s: %w", frontendClientID, err)
		}
		return true, id, nil
	}

	changed := false
	if !stringSlicesEqualUnordered(rep.RedirectUris, wantRedirects) {
		rep.RedirectUris = wantRedirects
		changed = true
	}
	if !stringSlicesEqualUnordered(rep.WebOrigins, wantOrigins) {
		rep.WebOrigins = wantOrigins
		changed = true
	}
	if !rep.PublicClient || !rep.StandardFlowEnabled {
		rep.PublicClient = true
		rep.StandardFlowEnabled = true
		changed = true
	}
	// Reconciled exactly like redirectUris/webOrigins above — a client that predates this
	// attribute must be repaired here too, not just at create time, or a live realm keeps
	// failing logout with KC's "invalid redirect uri" until a manual fix.
	if rep.Attributes[postLogoutRedirectURIsAttrKey] != postLogoutRedirectURIsAttrValue {
		setClientAttribute(&rep, postLogoutRedirectURIsAttrKey, postLogoutRedirectURIsAttrValue)
		changed = true
	}
	if changed {
		if err := kc.updateClient(ctx, rep.ID, rep); err != nil {
			return false, "", err
		}
	}
	return changed, rep.ID, nil
}

// setClientAttribute sets key=value on rep.Attributes, initializing the map if the client rep
// (e.g. one fetched from a pre-attribute-era realm) had none.
// reconcileServiceClient converges one confidential client with a service account and no
// interactive flow: its only way to a token is the client-credentials grant. The token's `sub`
// is the client's service-account user, which the gateway provisions like any other subject;
// what the service may do is decided by the memberships and tuples an administrator gives that
// subject, never by the client itself. The secret is Keycloak-generated and read from the admin
// console (Clients → <id> → Credentials); bootstrap never prints or stores it.
func reconcileServiceClient(ctx context.Context, kc *kcMasterClient, clientID string) (bool, string, error) {
	rep, found, err := kc.findClientByClientID(ctx, clientID)
	if err != nil {
		return false, "", err
	}
	if !found {
		id, err := kc.createClient(ctx, kcClientRep{
			ClientID: clientID, Name: "Kiban service " + clientID, Enabled: true, Protocol: "openid-connect",
			ServiceAccountsEnabled: true,
		})
		if err != nil {
			return false, "", fmt.Errorf("create %s: %w", clientID, err)
		}
		return true, id, nil
	}
	if rep.PublicClient || rep.BearerOnly || !rep.ServiceAccountsEnabled || rep.StandardFlowEnabled ||
		rep.DirectAccessGrantsEnabled || rep.ImplicitFlowEnabled || !rep.Enabled {
		rep.PublicClient, rep.BearerOnly, rep.ServiceAccountsEnabled = false, false, true
		rep.StandardFlowEnabled, rep.DirectAccessGrantsEnabled, rep.ImplicitFlowEnabled = false, false, false
		rep.Enabled = true
		if err := kc.updateClient(ctx, rep.ID, rep); err != nil {
			return false, "", err
		}
		return true, rep.ID, nil
	}
	return false, rep.ID, nil
}

func setClientAttribute(rep *kcClientRep, key, value string) {
	if rep.Attributes == nil {
		rep.Attributes = map[string]string{}
	}
	rep.Attributes[key] = value
}

func stringSlicesEqualUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa := append([]string{}, a...)
	sb := append([]string{}, b...)
	sort.Strings(sa)
	sort.Strings(sb)
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}

func reconcileAudienceMapper(ctx context.Context, kc *kcMasterClient, frontendInternalID string) (bool, error) {
	if frontendInternalID == "" {
		return false, fmt.Errorf("no internal client id for the audience mapper")
	}
	mappers, err := kc.protocolMappers(ctx, frontendInternalID)
	if err != nil {
		return false, err
	}
	wantConfig := map[string]string{
		"included.client.audience": apiClientID,
		"id.token.claim":           "false",
		"access.token.claim":       "true",
		"userinfo.token.claim":     "false",
	}

	// Reuse whichever audience mapper is present rather than creating a duplicate.
	var existing *kcProtocolMapperRep
	for i := range mappers {
		if mappers[i].ProtocolMapper == "oidc-audience-mapper" {
			existing = &mappers[i]
			break
		}
	}
	if existing == nil {
		if err := kc.createProtocolMapper(ctx, frontendInternalID, kcProtocolMapperRep{
			Name: audienceMapperName, Protocol: "openid-connect", ProtocolMapper: "oidc-audience-mapper", Config: wantConfig,
		}); err != nil {
			return false, err
		}
		return true, nil
	}
	// Only the AUDIENCE VALUE is functionally load-bearing (every service's KEYCLOAK_AUDIENCE
	// defaults to "kiban-api" — this is the bug this step actually fixes). The mapper's `name`
	// field is cosmetic and, empirically, some Keycloak versions don't honor a rename via this
	// PUT anyway — a differently-named mapper whose config targets "kiban-api" is intentionally
	// NOT treated as drift, so re-runs converge instead of endlessly reapplying a no-op rename.
	if existing.Config["included.client.audience"] == apiClientID {
		return false, nil
	}
	existing.Config = wantConfig
	if err := kc.updateProtocolMapper(ctx, frontendInternalID, existing.ID, *existing); err != nil {
		return false, err
	}
	return true, nil
}

func verifyMFAFlowWiring(ctx context.Context, kc *kcMasterClient) error {
	current, err := kc.getRealm(ctx)
	if err != nil {
		return err
	}
	if bf, _ := current["browserFlow"].(string); bf != browserFlowAlias {
		// reconcileRealmSettings already repairs this field; a mismatch here means the repair
		// didn't take (unexpected admin-API behavior) — fail loudly rather than silently
		// proceed with the wrong flow wired.
		return fmt.Errorf("realm browserFlow = %q after reconciliation, want %q", bf, browserFlowAlias)
	}

	executions, err := kc.flowExecutions(ctx, browserFlowAlias)
	if err != nil {
		return fmt.Errorf("read %q flow executions: %w", browserFlowAlias, err)
	}

	// Structural check FIRST, before the presence/requirement check below: a flow where
	// kiban-local-mfa-setup sits at the same level as ANY ALTERNATIVE execution is broken —
	// Keycloak silently discards the ALTERNATIVE executions at that level and evaluates the
	// REQUIRED one first, before any user is established, so EVERY interactive browser login
	// fails with "Invalid username or password". The presence/requirement check alone cannot
	// catch this: it only looks
	// at the mfa authenticator's own Requirement field, which reads REQUIRED in the broken
	// layout too — the bug is in the SIBLING structure, not that field.
	if err := verifyBrowserFlowStructure(executions); err != nil {
		// This step deliberately does not attempt to repair flow-level structure via the admin
		// API (same precedent as the "authenticator not found" case below: "this step does not
		// create authentication flows from scratch") — moving executions between levels needs
		// multi-call flow surgery (delete + recreate under a new subflow) that risks leaving a
		// half-migrated, ALSO-broken flow behind if it fails partway, which is worse than
		// failing loudly. The durable repair is `infra/keycloak-build/realm-kiban.json` itself
		// re-imported via `make dev-clean && make dev`; a live realm
		// that still shows this drift needs that re-import (or an equivalent manual admin-
		// console repair), not a partial runtime patch.
		return fmt.Errorf("realm: %q flow structure: %w (repair: `make dev-clean && make dev` to re-import the corrected infra/keycloak-build/realm-kiban.json, or fix the live flow manually in the admin console)", browserFlowAlias, err)
	}

	for _, ex := range executions {
		if ex.ProviderID == mfaAuthenticatorID {
			if ex.Requirement != "REQUIRED" {
				return fmt.Errorf("authenticator %q wired into %q with requirement %q, want REQUIRED", mfaAuthenticatorID, browserFlowAlias, ex.Requirement)
			}
			return nil
		}
	}
	return fmt.Errorf("authenticator %q not found in flow %q executions — MFA setup enforcement is not wired (manual realm repair needed; this step does not create authentication flows from scratch)", mfaAuthenticatorID, browserFlowAlias)
}

// reconcileDirectGrantFlow converges the realm's direct-grant flow on directGrantFlowAlias: a
// copy of Keycloak's built-in "direct grant" flow (username, password, conditional OTP) plus
// mfaAuthenticatorID as a REQUIRED top-level execution, bound as the realm's directGrantFlow.
// Every step is idempotent (create the flow only when absent, add the execution only when
// absent, set the requirement only when it differs, bind only when unbound).
func reconcileDirectGrantFlow(ctx context.Context, kc *kcMasterClient) (bool, error) {
	changed := false

	exists, err := kc.flowExists(ctx, directGrantFlowAlias)
	if err != nil {
		return false, fmt.Errorf("list flows: %w", err)
	}
	if !exists {
		if err := kc.copyFlow(ctx, builtinDirectGrantAlias, directGrantFlowAlias); err != nil {
			return false, fmt.Errorf("copy %q to %q: %w", builtinDirectGrantAlias, directGrantFlowAlias, err)
		}
		changed = true
	}

	executions, err := kc.flowExecutions(ctx, directGrantFlowAlias)
	if err != nil {
		return false, fmt.Errorf("read %q flow executions: %w", directGrantFlowAlias, err)
	}
	mfa := findExecution(executions, mfaAuthenticatorID)
	if mfa == nil {
		if err := kc.addFlowExecution(ctx, directGrantFlowAlias, mfaAuthenticatorID); err != nil {
			return false, fmt.Errorf("add %q to %q: %w", mfaAuthenticatorID, directGrantFlowAlias, err)
		}
		if executions, err = kc.flowExecutions(ctx, directGrantFlowAlias); err != nil {
			return false, fmt.Errorf("re-read %q flow executions: %w", directGrantFlowAlias, err)
		}
		if mfa = findExecution(executions, mfaAuthenticatorID); mfa == nil {
			return false, fmt.Errorf("authenticator %q not present in %q after adding it", mfaAuthenticatorID, directGrantFlowAlias)
		}
		changed = true
	}
	if mfa.Requirement != "REQUIRED" {
		if err := kc.setFlowExecutionRequirement(ctx, directGrantFlowAlias, mfa.ID, "REQUIRED"); err != nil {
			return false, fmt.Errorf("set %q REQUIRED in %q: %w", mfaAuthenticatorID, directGrantFlowAlias, err)
		}
		changed = true
	}

	current, err := kc.getRealm(ctx)
	if err != nil {
		return false, err
	}
	if bound, _ := current["directGrantFlow"].(string); bound != directGrantFlowAlias {
		if err := kc.updateRealm(ctx, map[string]any{"directGrantFlow": directGrantFlowAlias}); err != nil {
			return false, fmt.Errorf("bind realm directGrantFlow: %w", err)
		}
		changed = true
	}
	return changed, nil
}

func findExecution(executions []kcFlowExecutionRep, providerID string) *kcFlowExecutionRep {
	for i := range executions {
		if executions[i].ProviderID == providerID {
			return &executions[i]
		}
	}
	return nil
}

// verifyBrowserFlowStructure detects the invalid flow layout: any flow level (by Level, as
// returned by Keycloak's own executions listing) that mixes a REQUIRED execution with one or
// more ALTERNATIVE executions. Keycloak's flow engine treats that mix as invalid — it discards
// the ALTERNATIVE executions at that level and evaluates only the REQUIRED one, which is never
// correct for a browser flow meant to offer several alternative ways to establish a user
// (cookie / IdP redirect / forms) before any REQUIRED post-auth step runs.
func verifyBrowserFlowStructure(executions []kcFlowExecutionRep) error {
	byLevel := map[int][]kcFlowExecutionRep{}
	for _, ex := range executions {
		byLevel[ex.Level] = append(byLevel[ex.Level], ex)
	}
	for level, exs := range byLevel {
		var sawRequired, sawAlternative bool
		var names []string
		for _, ex := range exs {
			name := ex.ProviderID
			if name == "" {
				name = ex.DisplayName
			}
			names = append(names, fmt.Sprintf("%s=%s", name, ex.Requirement))
			switch ex.Requirement {
			case "REQUIRED":
				sawRequired = true
			case "ALTERNATIVE":
				sawAlternative = true
			}
		}
		if sawRequired && sawAlternative {
			sort.Strings(names)
			return fmt.Errorf("level %d mixes REQUIRED and ALTERNATIVE executions (invalid — Keycloak discards the ALTERNATIVE ones): %v", level, names)
		}
	}
	return nil
}

// verifyIdentityServiceRolesExact proves least privilege: the kiban-identity-service service
// account's realm-management client roles must be EXACTLY identityServiceRoles — missing roles
// are repaired (added); EXTRA roles are a hard stop — and it must hold NO realm role and no
// other client's roles at all (the composite role-mapping view is what makes this "exact":
// realm `admin`, `default-roles-<realm>` or a foreign client's role would otherwise be
// invisible to a check that only reads the realm-management mapping).
func verifyIdentityServiceRolesExact(ctx context.Context, kc *kcMasterClient) (string, error) {
	svcClient, found, err := kc.findClientByClientID(ctx, identityServiceClientID)
	if err != nil {
		return "", fmt.Errorf("find client %s: %w", identityServiceClientID, err)
	}
	if !found {
		return "", fmt.Errorf("client %s not found (expected from realm import)", identityServiceClientID)
	}
	userID, err := kc.serviceAccountUserID(ctx, svcClient.ID)
	if err != nil {
		return "", fmt.Errorf("service account user for %s: %w", identityServiceClientID, err)
	}
	realmMgmt, found, err := kc.findClientByClientID(ctx, realmManagementClientID)
	if err != nil {
		return "", fmt.Errorf("find client %s: %w", realmManagementClientID, err)
	}
	if !found {
		return "", fmt.Errorf("client %s not found (built into every realm)", realmManagementClientID)
	}

	all, err := kc.userRoleMappings(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("read composite role mappings: %w", err)
	}
	var foreign []string
	for _, r := range all.RealmMappings {
		foreign = append(foreign, "realm:"+r.Name)
	}
	for clientID, m := range all.ClientMappings {
		if clientID == realmManagementClientID {
			continue
		}
		for _, r := range m.Mappings {
			foreign = append(foreign, clientID+":"+r.Name)
		}
	}
	if len(foreign) > 0 {
		sort.Strings(foreign)
		return "", fmt.Errorf(
			"BLOCKED (exact-role verification): %s service account holds roles outside %s: %v (least privilege violated — repair manually, do not proceed)",
			identityServiceClientID, realmManagementClientID, foreign,
		)
	}

	assigned, err := kc.assignedClientRoles(ctx, userID, realmMgmt.ID)
	if err != nil {
		return "", fmt.Errorf("read assigned realm-management roles: %w", err)
	}
	assignedNames := make(map[string]bool, len(assigned))
	for _, r := range assigned {
		assignedNames[r.Name] = true
	}

	want := make(map[string]bool, len(identityServiceRoles))
	for _, r := range identityServiceRoles {
		want[r] = true
	}

	var extra, missing []string
	for name := range assignedNames {
		if !want[name] {
			extra = append(extra, name)
		}
	}
	for name := range want {
		if !assignedNames[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(extra)
	sort.Strings(missing)

	if len(extra) > 0 {
		return "", fmt.Errorf(
			"BLOCKED (exact-role verification): %s service account has EXTRA realm-management roles beyond the exact set %v: %v (least privilege violated — repair manually, do not proceed)",
			identityServiceClientID, identityServiceRoles, extra,
		)
	}

	if len(missing) == 0 {
		return fmt.Sprintf("identity service roles: converged (exactly %v)", identityServiceRoles), nil
	}

	available, err := kc.availableClientRoles(ctx, userID, realmMgmt.ID)
	if err != nil {
		return "", fmt.Errorf("read available realm-management roles: %w", err)
	}
	var toAdd []kcRoleRep
	for _, a := range available {
		for _, m := range missing {
			if a.Name == m {
				toAdd = append(toAdd, a)
			}
		}
	}
	if len(toAdd) != len(missing) {
		return "", fmt.Errorf("could not resolve missing role(s) %v in realm-management's available roles", missing)
	}
	if err := kc.addClientRoles(ctx, userID, realmMgmt.ID, toAdd); err != nil {
		return "", fmt.Errorf("add missing realm-management roles %v: %w", missing, err)
	}
	return fmt.Sprintf("identity service roles: repaired (added %v, now exactly %v)", missing, identityServiceRoles), nil
}

// writeServiceSecrets writes the identity client's secret to SecretsDir as a 0600 file.
// Rotation (--rotate-secrets) regenerates the secret via the admin API first;
// the file always reflects the CURRENT admin-API value, so re-running without --rotate-secrets
// after a rotation converges on the rotated value (never reverts it).
func writeServiceSecrets(ctx context.Context, kc *kcMasterClient, deps *Deps) (string, bool, error) {
	if deps.SecretsDir == "" {
		return "secrets: skipped (SecretsDir not set)", false, nil
	}

	svcClient, found, err := kc.findClientByClientID(ctx, identityServiceClientID)
	if err != nil {
		return "", false, err
	}
	if !found {
		return "", false, fmt.Errorf("client %s not found", identityServiceClientID)
	}

	secret := deps.IdentityClientSecret
	rotated := false
	if deps.RotateSecrets {
		newSecret, err := kc.regenerateClientSecret(ctx, svcClient.ID)
		if err != nil {
			return "", false, fmt.Errorf("rotate %s secret: %w", identityServiceClientID, err)
		}
		secret = newSecret
		rotated = true
	} else if secret == "" {
		current, err := kc.clientSecret(ctx, svcClient.ID)
		if err != nil {
			return "", false, fmt.Errorf("read %s secret: %w", identityServiceClientID, err)
		}
		secret = current
	}

	if err := os.MkdirAll(deps.SecretsDir, 0o700); err != nil {
		return "", false, fmt.Errorf("mkdir %s: %w", deps.SecretsDir, err)
	}
	path := filepath.Join(deps.SecretsDir, "keycloak-identity-client-secret")

	existing, readErr := os.ReadFile(path)
	changed := rotated || readErr != nil || string(existing) != secret
	if changed {
		if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
			return "", false, fmt.Errorf("write %s: %w", path, err)
		}
	}
	// The consumer is the identity service, which runs as the app images' fixed uid
	// (infra/Dockerfile.service's 65532) and reads the file via
	// KEYCLOAK_IDENTITY_CLIENT_SECRET_FILE; bootstrap itself runs as root, so a 0600 file must be
	// handed to that uid or identity cannot open it. Best-effort when bootstrap is not root
	// (then the file is already owned by whoever runs it).
	if os.Geteuid() == 0 {
		if err := os.Chown(path, serviceUID, serviceUID); err != nil {
			return "", false, fmt.Errorf("chown %s to uid %d: %w", path, serviceUID, err)
		}
	}

	detail := fmt.Sprintf("secrets: identity client secret written to %s (%s)", path, outcomeWord(changed))
	if rotated {
		detail += " — ROTATED: operator must update KEYCLOAK_IDENTITY_CLIENT_SECRET (env/compose) to match, or the running identity service will keep using its old value until restarted with the new one"
	}
	return detail, changed, nil
}
