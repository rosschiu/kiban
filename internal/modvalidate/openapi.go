// SPDX-License-Identifier: Apache-2.0

package modvalidate

import (
	"sort"
	"strings"
)

var httpMethods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// validateOpenAPI runs the contract's OpenAPI fragment rules automatable from a generic parse of the
// YAML document: every operation needs operationId, every path lives under service.basePath
// (enforced via servers[0].url, since path keys are declared relative to it — see notification's
// own openapi.yaml), and every module-scoped operation (everything except the unauthenticated
// health/ready probes) carries a capability annotation (x-required-modules, non-empty).
func validateOpenAPI(moduleKey, basePath string, doc map[string]any) []ValidationError {
	var errs []ValidationError
	mk := moduleKey

	if servers, ok := doc["servers"].([]any); ok && len(servers) > 0 {
		for i, raw := range servers {
			srv, _ := raw.(map[string]any)
			url, _ := srv["url"].(string)
			switch {
			case i == 0 && url != basePath:
				errs = append(errs, errf(mk, RuleOpenAPIPathOutsideBasePath,
					"openapi.yaml: servers[0].url %q must equal service.basePath %q — every path key is declared relative to it", url, basePath))
			case i > 0 && url != "/":
				// The only sanctioned extra server is "/" for the bare /health and /ready probes.
				errs = append(errs, errf(mk, RuleOpenAPIPathOutsideBasePath,
					"openapi.yaml: servers[%d].url %q: the only server besides basePath is \"/\" (health/ready probes)", i, url))
			}
		}
	} else {
		errs = append(errs, errf(mk, RuleOpenAPIPathOutsideBasePath, "openapi.yaml: no servers[0].url declared; cannot confirm paths live under basePath %q", basePath))
	}

	paths, _ := doc["paths"].(map[string]any)
	pathKeys := make([]string, 0, len(paths))
	for p := range paths {
		pathKeys = append(pathKeys, p)
	}
	sort.Strings(pathKeys)

	seenOperationIDs := map[string]string{} // operationId -> "METHOD path", duplicate detection
	for _, pathKey := range pathKeys {
		item, ok := paths[pathKey].(map[string]any)
		if !ok {
			continue
		}
		// /ready (a DB-ping readiness probe, unauthenticated, same shape as
		// /health) is exempt for the same reason /health is — neither is a module-scoped
		// business operation, both are infra probes registry's own catalog (HealthPath) and
		// every module's mountRoutes treat identically (bare path, outside service.basePath).
		isHealthProbe := pathKey == "/health" || pathKey == "/ready"
		// Path keys are relative to basePath: an absolute API path (`/api/other/...`, or this
		// module's own basePath repeated) is outside basePath however servers[] is declared.
		if !strings.HasPrefix(pathKey, "/") || strings.HasPrefix(pathKey, "/api/") {
			errs = append(errs, errf(mk, RuleOpenAPIPathOutsideBasePath,
				"openapi.yaml: path %q must be declared relative to service.basePath %q (start with \"/\", never \"/api/\")", pathKey, basePath))
		}
		for _, method := range httpMethods {
			opRaw, ok := item[method]
			if !ok {
				continue
			}
			op, ok := opRaw.(map[string]any)
			if !ok {
				continue
			}
			opID, _ := op["operationId"].(string)
			if opID == "" {
				errs = append(errs, errf(mk, RuleOpenAPIOperationID,
					"openapi.yaml: %s %s: missing operationId", method, pathKey))
			} else if prev, dup := seenOperationIDs[opID]; dup {
				errs = append(errs, errf(mk, RuleOpenAPIOperationID,
					"openapi.yaml: %s %s: duplicate operationId %q (already used by %s)", method, pathKey, opID, prev))
			} else {
				seenOperationIDs[opID] = method + " " + pathKey
			}

			if !isHealthProbe {
				mods, ok := op["x-required-modules"].([]any)
				if !ok || len(mods) == 0 {
					errs = append(errs, errf(mk, RuleOpenAPIMissingCapabilityAnnotation,
						"openapi.yaml: %s %s: module-scoped operation missing a non-empty x-required-modules capability annotation", method, pathKey))
				}
			}
		}
	}

	return errs
}

// openAPIRequiredModules returns every module key named by an x-required-modules annotation in
// the document (deduplicated, sorted) — the catalog-level check resolves them against the batch
// and snapshot (so `x-required-modules: [nonexistent]` is refused).
func openAPIRequiredModules(doc map[string]any) []string {
	set := map[string]bool{}
	paths, _ := doc["paths"].(map[string]any)
	for _, item := range paths {
		ops, _ := item.(map[string]any)
		for _, method := range httpMethods {
			op, _ := ops[method].(map[string]any)
			mods, _ := op["x-required-modules"].([]any)
			for _, m := range mods {
				if s, ok := m.(string); ok {
					set[s] = true
				}
			}
		}
	}
	return sortedKeys(set)
}
