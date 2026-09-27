// SPDX-License-Identifier: Apache-2.0

package modulekit

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestBearerFromHeader(t *testing.T) {
	cases := map[string]string{
		"Bearer abc":  "abc",
		"bearer abc":  "abc",
		"BEARER abc":  "abc",
		"Bearer ":     "",
		"Basic abc":   "",
		"":            "",
		"Bearerabc":   "",
		"Bearer a b ": "a b ",
	}
	for in, want := range cases {
		if got := BearerFromHeader(in); got != want {
			t.Errorf("BearerFromHeader(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParsePathUUID(t *testing.T) {
	mux := http.NewServeMux()
	var got uuid.UUID
	var ok bool
	mux.HandleFunc("GET /x/{id}", func(w http.ResponseWriter, r *http.Request) {
		got, ok = ParsePathUUID(w, r, "id")
		if ok {
			w.WriteHeader(http.StatusNoContent)
		}
	})
	id := uuid.New()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x/"+id.String(), nil))
	if !ok || got != id || rec.Code != http.StatusNoContent {
		t.Fatalf("valid uuid: ok=%v got=%s code=%d", ok, got, rec.Code)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x/nope", nil))
	if ok || rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid uuid: ok=%v code=%d", ok, rec.Code)
	}
	var body struct {
		Error struct {
			Code    string            `json:"code"`
			Message string            `json:"message"`
			Details map[string]string `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "BAD_REQUEST" || body.Error.Message != "id must be a valid UUID" || body.Error.Details["field"] != "id" {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestPageParams(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/?page=3&pageSize=7", nil)
	if p, s := PageParams(r); p != 3 || s != 7 {
		t.Fatalf("got (%d, %d)", p, s)
	}
	r = httptest.NewRequest(http.MethodGet, "/?page=x", nil)
	if p, s := PageParams(r); p != 0 || s != 0 {
		t.Fatalf("got (%d, %d), want zeros for unparseable/missing", p, s)
	}
}

func TestClampPage(t *testing.T) {
	cases := []struct{ p, s, wp, ws int }{
		{0, 0, 1, 25}, {-1, -5, 1, 25}, {2, 10, 2, 10}, {1, 1000, 1, 100}, {1, 100, 1, 100},
	}
	for _, c := range cases {
		if p, s := ClampPage(c.p, c.s); p != c.wp || s != c.ws {
			t.Errorf("ClampPage(%d, %d) = (%d, %d), want (%d, %d)", c.p, c.s, p, s, c.wp, c.ws)
		}
	}
}

func TestDecodeJSON(t *testing.T) {
	type in struct {
		Name string `json:"name"`
	}
	rec := httptest.NewRecorder()
	var v in
	if !DecodeJSON(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"a"}`)), &v) || v.Name != "a" {
		t.Fatalf("valid body: ok=false or v=%+v", v)
	}

	rec = httptest.NewRecorder()
	if DecodeJSON(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{`)), &v) || rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid JSON body") {
		t.Fatalf("malformed: code=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Body = nil
	if DecodeJSON(rec, r, &v) || rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "request body required") {
		t.Fatalf("nil body: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestWritePage(t *testing.T) {
	rec := httptest.NewRecorder()
	WritePage(rec, []int{1, 2, 3}, 51, 0, 0, func(i int) string { return strings.Repeat("x", i) })
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	var body struct {
		Data struct {
			Items      []string `json:"items"`
			Total      int      `json:"total"`
			Page       int      `json:"page"`
			PageSize   int      `json:"pageSize"`
			TotalPages int      `json:"totalPages"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	d := body.Data
	if len(d.Items) != 3 || d.Items[2] != "xxx" || d.Total != 51 || d.Page != 1 || d.PageSize != 25 || d.TotalPages != 3 {
		t.Fatalf("data = %+v", d)
	}

	rec = httptest.NewRecorder()
	WritePage(rec, []int{}, 0, 1, 10, func(i int) int { return i })
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.TotalPages != 1 {
		t.Fatalf("empty page totalPages = %d, want 1", body.Data.TotalPages)
	}
}

type sqlStateErr string

func (e sqlStateErr) Error() string    { return string(e) }
func (e sqlStateErr) SQLState() string { return string(e) }

func TestIsUniqueViolation(t *testing.T) {
	if !IsUniqueViolation(sqlStateErr("23505")) {
		t.Fatal("23505 must be a unique violation")
	}
	if !IsUniqueViolation(errors.Join(errors.New("wrapped"), sqlStateErr("23505"))) {
		t.Fatal("wrapped 23505 must be a unique violation")
	}
	if IsUniqueViolation(sqlStateErr("23503")) || IsUniqueViolation(errors.New("plain")) || IsUniqueViolation(nil) {
		t.Fatal("non-23505 must not be a unique violation")
	}
}
