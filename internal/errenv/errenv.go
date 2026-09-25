// SPDX-License-Identifier: Apache-2.0

// Package errenv defines the platform's error and success envelope shapes,
// the canonical error codes, and HTTP writers for both. Shapes are contract
// and must not vary.
package errenv

import (
	"encoding/json"
	"net/http"
)

// Canonical error codes. Exact strings are contract.
const (
	CodeBadRequest               = "BAD_REQUEST"
	CodeAuthTokenMissing         = "AUTH_TOKEN_MISSING"
	CodeAuthTokenInvalid         = "AUTH_TOKEN_INVALID"
	CodeForbidden                = "FORBIDDEN"
	CodeAuthorizationDenied      = "AUTHORIZATION_DENIED"
	CodeModuleNotInstalled       = "MODULE_NOT_INSTALLED"
	CodeModuleDisabled           = "MODULE_DISABLED"
	CodeModuleDependencyMissing  = "MODULE_DEPENDENCY_MISSING"
	CodeNotFound                 = "NOT_FOUND"
	CodeConflict                 = "CONFLICT"
	CodeValidationError          = "VALIDATION_ERROR"
	CodeInternalError            = "INTERNAL_ERROR"
	CodeAuthorizationUnavailable = "AUTHORIZATION_UNAVAILABLE"
	// CodeModuleUnavailable is the gateway's 503 for a module the registry catalog resolves
	// but whose backend cannot be reached.
	CodeModuleUnavailable = "MODULE_UNAVAILABLE"
	// CodePayloadTooLarge is the gateway's 413 for a request body over the edge's cap (32 MB on
	// the module proxy, 1 MB elsewhere) — the client's fault, never an upstream outage.
	CodePayloadTooLarge = "PAYLOAD_TOO_LARGE"
	// CodeValidationFailed is a 422 for a domain-policy rejection distinct from ordinary field
	// shape validation (CodeValidationError) — e.g. the notifications webhook SSRF target
	// policy at channel-create time. Shared here rather than duplicated per module.
	CodeValidationFailed = "VALIDATION_FAILED"
	// CodeIdempotencyConflict is the 409 for the same Idempotency-Key reused with a different
	// request payload.
	CodeIdempotencyConflict = "IDEMPOTENCY_CONFLICT"
	// CodeGroupExternallyManaged is the 409 for the group single-writer invariant: a membership
	// write (add/remove) was attempted against a group whose source is not "kiban" — every
	// human/API path gets this exact code, never a bare CONFLICT.
	CodeGroupExternallyManaged = "GROUP_EXTERNALLY_MANAGED"
	// CodeAssignmentAlreadyEnded is the 409 for ending a position assignment whose window is
	// already closed (valid_to set) — nothing is rewritten, no tuple is revoked.
	CodeAssignmentAlreadyEnded = "ASSIGNMENT_ALREADY_ENDED"
)

// APIError is the wire shape of an error, nested under "error" in the
// response envelope: {"error":{"code","message","details"?}}.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// errorEnvelope is the top-level wire shape for an error response.
type errorEnvelope struct {
	Error APIError `json:"error"`
}

// dataEnvelope is the top-level wire shape for a success response.
type dataEnvelope struct {
	Data any `json:"data"`
}

// Page is the offset-pagination wire shape.
type Page[T any] struct {
	Items      []T `json:"items"`
	Total      int `json:"total"`
	Page       int `json:"page"`
	PageSize   int `json:"pageSize"`
	TotalPages int `json:"totalPages"`
}

// WriteError writes the error envelope with the given HTTP status.
func WriteError(w http.ResponseWriter, status int, apiErr APIError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorEnvelope{Error: apiErr})
}

// WriteData writes the success envelope with the given HTTP status.
func WriteData(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(dataEnvelope{Data: v})
}
