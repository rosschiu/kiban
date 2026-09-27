// SPDX-License-Identifier: Apache-2.0

//go:build live

package identity

import (
	"context"
	"fmt"
)

// GetUserAttribute reads a single Keycloak user attribute's first value, "" if unset. Only the
// live sync tests use it, to confirm a sync actually reached Keycloak — hence the build tag.
func (c *AdminClient) GetUserAttribute(ctx context.Context, kcSub, key string) (string, error) {
	user, err := c.getUser(ctx, kcSub)
	if err != nil {
		return "", fmt.Errorf("identity: get user attribute: %w", err)
	}
	attrs, _ := user["attributes"].(map[string]any)
	if attrs == nil {
		return "", nil
	}
	values, ok := attrs[key].([]any)
	if !ok || len(values) == 0 {
		return "", nil
	}
	s, _ := values[0].(string)
	return s, nil
}
