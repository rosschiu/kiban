// SPDX-License-Identifier: Apache-2.0

package modvalidate

import (
	"sort"
	"strconv"
)

// occurrence records where a catalog value (moduleKey, basePath, route id, feature key, object
// type) was first seen, so a duplicate's error message names both offenders.
type occurrence struct {
	moduleKey string
	value     string
}

// validateCatalogDuplicates rejects "duplicate moduleKey / API prefix / route id / feature key /
// object type across the catalog" — across the current validate batch AND an optional external
// catalog snapshot (so tests can run against synthetic catalogs).
func validateCatalogDuplicates(modules []*Module, snapshot CatalogSnapshot) []ValidationError {
	var errs []ValidationError

	moduleKeys := map[string][]occurrence{}
	basePaths := map[string][]occurrence{}
	ports := map[string][]occurrence{}
	routeIDs := map[string][]occurrence{}
	featureKeys := map[string][]occurrence{}
	objectTypes := map[string][]occurrence{}

	addOcc := func(m map[string][]occurrence, moduleKey, value string) {
		if value == "" {
			return
		}
		m[value] = append(m[value], occurrence{moduleKey: moduleKey, value: value})
	}
	portKey := func(p int) string {
		if p == 0 {
			return ""
		}
		return strconv.Itoa(p)
	}

	for _, mod := range modules {
		if mod.Manifest == nil {
			continue
		}
		mk := mod.Manifest.ModuleKey
		addOcc(moduleKeys, mk, mk)
		addOcc(basePaths, mk, mod.Manifest.Service.BasePath)
		addOcc(ports, mk, portKey(mod.Manifest.Service.Port))
		for _, id := range routeIDsOf(mod.Frontend) {
			addOcc(routeIDs, mk, id)
		}
		for _, fk := range fragmentFeatureKeys(mod.Fragment) {
			addOcc(featureKeys, mk, fk)
		}
		for _, ot := range fragmentObjectTypes(mod.Fragment) {
			addOcc(objectTypes, mk, ot)
		}
	}

	for _, e := range snapshot.Modules {
		addOcc(moduleKeys, e.ModuleKey, e.ModuleKey)
		addOcc(basePaths, e.ModuleKey, e.BasePath)
		addOcc(ports, e.ModuleKey, portKey(e.Port))
		for _, id := range e.RouteIDs {
			addOcc(routeIDs, e.ModuleKey, id)
		}
		for _, fk := range e.FeatureKeys {
			addOcc(featureKeys, e.ModuleKey, fk)
		}
		for _, ot := range e.ObjectTypes {
			addOcc(objectTypes, e.ModuleKey, ot)
		}
	}

	errs = append(errs, reportDuplicates(moduleKeys, RuleDuplicateModuleKey, "moduleKey")...)
	errs = append(errs, reportDuplicates(basePaths, RuleDuplicateBasePath, "service.basePath")...)
	errs = append(errs, reportDuplicates(ports, RuleDuplicatePort, "service.port")...)
	errs = append(errs, reportDuplicates(routeIDs, RuleDuplicateRouteID, "frontend route id")...)
	errs = append(errs, reportDuplicates(featureKeys, RuleDuplicateFeatureKey, "authz feature key")...)
	errs = append(errs, reportDuplicates(objectTypes, RuleDuplicateObjectType, "authz object type")...)

	// x-required-modules must name modules the catalog knows (this batch or the snapshot).
	for _, mod := range modules {
		if mod.Manifest == nil || mod.OpenAPI == nil {
			continue
		}
		for _, req := range openAPIRequiredModules(mod.OpenAPI) {
			if _, ok := moduleKeys[req]; !ok {
				errs = append(errs, errf(mod.Manifest.ModuleKey, RuleOpenAPIUnknownRequiredModule,
					"openapi.yaml: x-required-modules names %q, which is not a module in this batch or the supplied catalog snapshot", req))
			}
		}
	}

	return errs
}

func routeIDsOf(fe *FrontendManifest) []string {
	if fe == nil {
		return nil
	}
	out := make([]string, 0, len(fe.Routes))
	for _, r := range fe.Routes {
		out = append(out, r.ID)
	}
	return out
}

func reportDuplicates(occs map[string][]occurrence, rule, label string) []ValidationError {
	var errs []ValidationError
	var values []string
	for v := range occs {
		values = append(values, v)
	}
	sort.Strings(values)
	for _, v := range values {
		list := occs[v]
		if len(list) < 2 {
			continue
		}
		owners := make([]string, 0, len(list))
		for _, o := range list {
			owners = append(owners, o.moduleKey)
		}
		// Every module that shares the duplicated value gets its own named error (so a batch
		// with modules A and B both claiming basePath /api/foo produces an error attributed to
		// each, not just one).
		for _, o := range list {
			errs = append(errs, errf(o.moduleKey, rule,
				"%s %q is claimed by more than one module: %v", label, v, owners))
		}
	}
	return errs
}
