// SPDX-License-Identifier: Apache-2.0

// Company-administrator access to the org admin routes: a superadmin may manage any company;
// an administrator of a company (the base model's `company:<id>#admin` relation) may manage
// that company's members, positions, assignments and groups. Companies and org units stay
// superadmin work. The gateway names the company from the request (path, query or body) or,
// for routes that only carry a resource id, from org's own read of that resource; org then
// re-decides the same question on every write (internal/org/http.go's authorizeInCompany),
// so this guard is defence in depth for writes and the only guard for reads.
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/rosschiu/kiban/internal/errenv"
	"github.com/rosschiu/kiban/internal/obs"
)

// errCompanyNotFound: the resource the request names does not exist (answered 404 before any
// authorization decision; the id is not a secret). errCompanyUnnamed: the request does not
// name a company where it must (a missing or malformed field: 400).
var (
	errCompanyNotFound = errors.New("gateway: company resource not found")
	errCompanyUnnamed  = errors.New("gateway: request names no company")
)

// companyOfFunc names the company a request is about, or errCompanyNotFound, or any other
// error (answered 503: fail closed).
type companyOfFunc func(r *http.Request) (string, error)

// DecideAdminInCompany is DecideAdmin's company-scope twin: superadmin or company admin.
func (c *AuthzAdminClient) DecideAdminInCompany(ctx context.Context, authorizationHeader, action, companyID, correlationID string) adminResult {
	d, err := c.inner.DecideInCompany(ctx, authorizationHeader, action, companyID, correlationID)
	if err != nil {
		return adminUncertain
	}
	if d.Allowed && d.Reason == "ALLOWED" {
		return adminAllowed
	}
	if d.Denied() {
		return adminDenied
	}
	return adminUncertain
}

// DecideMemberInCompany: superadmin or any active member of the company (reads of a
// company's own facts).
func (c *AuthzAdminClient) DecideMemberInCompany(ctx context.Context, authorizationHeader, action, companyID, correlationID string) adminResult {
	d, err := c.inner.DecideMemberInCompany(ctx, authorizationHeader, action, companyID, correlationID)
	if err != nil {
		return adminUncertain
	}
	if d.Allowed && d.Reason == "ALLOWED" {
		return adminAllowed
	}
	if d.Denied() {
		return adminDenied
	}
	return adminUncertain
}

// RequireSuperadminOrCompanyAdmin guards a route whose subject is one company: allowed for the
// superadmin and for an administrator of that company, 403 for everyone else, 503 whenever the
// company or the decision cannot be established.
func RequireSuperadminOrCompanyAdmin(client *AuthzAdminClient, action string, companyOf companyOfFunc) func(http.Handler) http.Handler {
	return requireInCompany(client, action, companyOf, (*AuthzAdminClient).DecideAdminInCompany, "requires superadmin access or administrator access to this company")
}

// RequireSuperadminOrCompanyMember guards a read of a company's own facts (a position's
// holder, a group's members): the superadmin or any active member of that company, which
// includes an app's service account once it is a member there.
func RequireSuperadminOrCompanyMember(client *AuthzAdminClient, action string, companyOf companyOfFunc) func(http.Handler) http.Handler {
	return requireInCompany(client, action, companyOf, (*AuthzAdminClient).DecideMemberInCompany, "requires membership of this company")
}

// requireResourceInCompany answers 404 when the resource named by pathParam does not belong
// to the company named by the companyId path value, so a company-scoped read cannot reach into
// another company's positions or groups by id.
func requireResourceInCompany(orgTarget *url.URL, kind, pathParam string) func(http.Handler) http.Handler {
	lookup := companyFromOrg(orgTarget, kind, pathParam)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			owner, err := lookup(r)
			switch {
			case errors.Is(err, errCompanyNotFound), err == nil && owner != r.PathValue("companyId"):
				errenv.WriteError(w, http.StatusNotFound, errenv.APIError{Code: errenv.CodeNotFound, Message: "not found"})
				return
			case err != nil:
				writeAdminUnavailable(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type decideInCompanyFunc func(c *AuthzAdminClient, ctx context.Context, authorizationHeader, action, companyID, correlationID string) adminResult

func requireInCompany(client *AuthzAdminClient, action string, companyOf companyOfFunc, decide decideInCompanyFunc, deniedMessage string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, hasAuth := AuthFromContext(r.Context())
			bearerHeader := r.Header.Get("Authorization")
			if client == nil || !hasAuth || bearerHeader == "" {
				writeAdminUnavailable(w)
				return
			}
			companyID, err := companyOf(r)
			switch {
			case errors.Is(err, errCompanyNotFound):
				errenv.WriteError(w, http.StatusNotFound, errenv.APIError{Code: errenv.CodeNotFound, Message: "not found"})
				return
			case errors.Is(err, errCompanyUnnamed):
				errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: err.Error()})
				return
			case err != nil || companyID == "":
				writeAdminUnavailable(w)
				return
			}
			correlationID, _ := obs.CorrelationFromContext(r.Context())
			switch decide(client, r.Context(), bearerHeader, action, companyID, correlationID) {
			case adminAllowed:
				next.ServeHTTP(w, r)
			case adminDenied:
				errenv.WriteError(w, http.StatusForbidden, errenv.APIError{
					Code:    errenv.CodeForbidden,
					Message: deniedMessage,
				})
			default:
				writeAdminUnavailable(w)
			}
		})
	}
}

func companyFromPath(param string) companyOfFunc {
	return func(r *http.Request) (string, error) { return r.PathValue(param), nil }
}

func companyFromQuery(param string) companyOfFunc {
	return func(r *http.Request) (string, error) {
		v := r.URL.Query().Get(param)
		if v == "" {
			return "", fmt.Errorf("%w: %s query parameter required", errCompanyUnnamed, param)
		}
		return v, nil
	}
}

// companyFromBody reads the JSON body's field and puts the body back for the proxy.
func companyFromBody(field string) companyOfFunc {
	return func(r *http.Request) (string, error) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			return "", err
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			return "", fmt.Errorf("%w: body is not JSON", errCompanyUnnamed)
		}
		v, _ := body[field].(string)
		if v == "" {
			return "", fmt.Errorf("%w: body field %s required", errCompanyUnnamed, field)
		}
		return v, nil
	}
}

var orgLookupClient = &http.Client{Timeout: 5 * time.Second}

// companyFromOrg names the company of an org resource (`members`, `positions`, `assignments`,
// `groups`) by reading it from org: GET <orgTarget>/internal/org/<kind>/<id> answers a view
// with `companyId`. 404 from org is errCompanyNotFound.
func companyFromOrg(orgTarget *url.URL, kind, pathParam string) companyOfFunc {
	return func(r *http.Request) (string, error) {
		id := r.PathValue(pathParam)
		u := *orgTarget
		u.Path = "/internal/org/" + kind + "/" + url.PathEscape(id)
		u.RawQuery = ""
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u.String(), nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", r.Header.Get("Authorization"))
		resp, err := orgLookupClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return "", errCompanyNotFound
		}
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("gateway: org lookup of %s %s: status %d", kind, id, resp.StatusCode)
		}
		var env struct {
			Data struct {
				CompanyID string `json:"companyId"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
			return "", err
		}
		if env.Data.CompanyID == "" {
			return "", fmt.Errorf("gateway: org lookup of %s %s: no companyId", kind, id)
		}
		return env.Data.CompanyID, nil
	}
}
