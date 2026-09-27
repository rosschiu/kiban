// SPDX-License-Identifier: Apache-2.0

package modulekit

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/errenv"
)

// MuxHandleFunc is the minimal surface a module's route mounter needs from a mux —
// *http.ServeMux satisfies it structurally, and so does a route recorder in tests.
type MuxHandleFunc interface {
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

// BearerFromHeader returns the token half of a "Bearer <token>" Authorization header value
// (scheme matched case-insensitively), or "" when the value is not a bearer credential.
func BearerFromHeader(v string) string {
	const prefix = "Bearer "
	if len(v) > len(prefix) && strings.EqualFold(v[:len(prefix)], prefix) {
		return v[len(prefix):]
	}
	return ""
}

// ParsePathUUID parses the named path value as a UUID, writing the 400 envelope on failure.
func ParsePathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: name + " must be a valid UUID", Details: map[string]string{"field": name}})
		return uuid.UUID{}, false
	}
	return id, true
}

// PageParams reads ?page and ?pageSize (unparseable values read as 0; ClampPage normalises).
func PageParams(r *http.Request) (int, int) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("pageSize"))
	return page, pageSize
}

// DecodeJSON decodes the request body into v, writing the 400 envelope on a missing body or
// malformed JSON.
func DecodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Body == nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "request body required"})
		return false
	}
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid JSON body"})
		return false
	}
	return true
}

// ClampPage normalises pagination: page >= 1, pageSize in [1, 100] with 25 as the default.
func ClampPage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 25
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}

// WritePage writes the 200 errenv.Page envelope for one page of items mapped through toWire.
func WritePage[T any, W any](w http.ResponseWriter, items []T, total, page, pageSize int, toWire func(T) W) {
	page, pageSize = ClampPage(page, pageSize)
	wire := make([]W, len(items))
	for i, it := range items {
		wire[i] = toWire(it)
	}
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}
	errenv.WriteData(w, http.StatusOK, errenv.Page[W]{Items: wire, Total: total, Page: page, PageSize: pageSize, TotalPages: totalPages})
}

// IsUniqueViolation reports whether err is a Postgres unique_violation (SQLSTATE 23505).
func IsUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
