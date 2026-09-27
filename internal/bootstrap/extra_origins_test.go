// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"slices"
	"testing"
)

func TestFrontendOrigins_Extra(t *testing.T) {
	redirects, origins := frontendOrigins("kiban.example", []string{"https://app.example.com/", "com.example.app:/callback"})
	if !slices.Equal(redirects, []string{"https://kiban.example/*", "https://app.example.com/*", "com.example.app:/callback"}) {
		t.Errorf("redirects = %v", redirects)
	}
	if !slices.Equal(origins, []string{"https://kiban.example", "https://app.example.com"}) {
		t.Errorf("origins = %v (a custom-scheme redirect is never a web origin)", origins)
	}
}
