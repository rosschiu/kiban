// SPDX-License-Identifier: Apache-2.0

package modvalidate

import (
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
)

var routeParamPattern = regexp.MustCompile(`^:[a-zA-Z_][a-zA-Z0-9_]*$`)
var routeSegmentPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// validateFrontend runs every frontend.manifest.json contract rule automatable from the frontend
// manifest plus its owning fragment: routeBase congruence, duplicate route ids, structural path
// collisions, bad param names, and feature keys absent from the authz fragment (with the one
// documented exception — see syntheticAccessFeatureKey).
func validateFrontend(moduleKey string, fe *FrontendManifest, fragment *AuthzFragment) []ValidationError {
	var errs []ValidationError
	mk := moduleKey

	if fe.ModuleKey != moduleKey {
		errs = append(errs, errf(mk, RuleFragmentModuleKeyMismatch,
			"frontend.manifest.json: moduleKey %q does not match module.manifest.json's moduleKey %q", fe.ModuleKey, moduleKey))
	}

	wantRouteBase := "/app/" + moduleKey
	if fe.RouteBase != wantRouteBase {
		errs = append(errs, errf(mk, RuleRouteBaseMismatch,
			"frontend.manifest.json: routeBase %q must equal %q (moduleKey %q)", fe.RouteBase, wantRouteBase, moduleKey))
	}

	if _, err := semver.NewConstraint(fe.SdkVersionRange); err != nil {
		errs = append(errs, errf(mk, RuleFrontendSDKVersionRange,
			"frontend.manifest.json: sdkVersionRange %q is not a valid semver range: %v", fe.SdkVersionRange, err))
	}

	allowedFeatureKeys := fragmentFeatureKeySet(fragment)
	syntheticKey := syntheticAccessFeatureKey(moduleKey)

	seenIDs := map[string]bool{}
	seenPaths := map[string]string{} // normalized path -> route id, collision detection
	for _, route := range fe.Routes {
		if seenIDs[route.ID] {
			errs = append(errs, errf(mk, RuleFrontendDuplicateRouteID,
				"frontend.manifest.json: duplicate route id %q", route.ID))
		}
		seenIDs[route.ID] = true

		norm := normalizeRoutePath(route.Path)
		if prev, dup := seenPaths[norm]; dup {
			errs = append(errs, errf(mk, RuleFrontendPathCollision,
				"frontend.manifest.json: route %q's path %q collides with route %q", route.ID, route.Path, prev))
		} else {
			seenPaths[norm] = route.ID
		}

		for _, seg := range strings.Split(route.Path, "/") {
			if seg == "" {
				continue
			}
			if strings.HasPrefix(seg, ":") {
				if !routeParamPattern.MatchString(seg) {
					errs = append(errs, errf(mk, RuleFrontendBadParamName,
						"frontend.manifest.json: route %q: bad param segment %q", route.ID, seg))
				}
				continue
			}
			if !routeSegmentPattern.MatchString(seg) {
				errs = append(errs, errf(mk, RuleFrontendBadParamName,
					"frontend.manifest.json: route %q: bad path segment %q", route.ID, seg))
			}
		}

		if route.FeatureKey != syntheticKey && !allowedFeatureKeys[route.FeatureKey] {
			errs = append(errs, errf(mk, RuleFrontendFeatureKeyMissing,
				"frontend.manifest.json: route %q's featureKey %q is not declared in authz.fragment.json's features (and is not the synthesized %q key)",
				route.ID, route.FeatureKey, syntheticKey))
		}
	}

	return errs
}

// normalizeRoutePath collapses param segments to a single placeholder so that e.g. "channels/:id"
// and "channels/:channelId" are correctly flagged as a structural collision (same shape, same
// mount point) regardless of param naming.
func normalizeRoutePath(p string) string {
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		if strings.HasPrefix(seg, ":") {
			segs[i] = ":*"
		}
	}
	return strings.Join(segs, "/")
}
