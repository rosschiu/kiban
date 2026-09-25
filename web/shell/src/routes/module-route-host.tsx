// SPDX-License-Identifier: Apache-2.0

// Shared body for both dynamic module route hosts. Pure
// resolver.ts decides the outcome; this component is the thin React translation of that outcome
// into one of the four designed states, or the resolved module page.
import { Suspense } from "react";
import { useModuleAccess } from "../nav/module-access";
import { localModuleCatalog, localModuleRegistry } from "../modules/registry";
import { resolveModuleRoute, type ModuleScope } from "../resolver/resolver";
import { ModuleErrorBoundary } from "../ui/error-boundary";
import { AccessDeniedState, ModuleErrorState, ModuleLoadingState, ModuleUnavailableState, RouteNotFoundState } from "./states";

export interface ModuleRouteHostProps {
  hostScope: ModuleScope;
  moduleKey: string;
  modulePath?: string;
  companyId?: string;
}

export function ModuleRouteHost({ hostScope, moduleKey, modulePath, companyId }: ModuleRouteHostProps) {
  const { access, ready } = useModuleAccess();
  // Never render a terminal outcome from the not-yet-loaded composition — the
  // resolver cannot tell "empty because loading" from "empty because denied/uninstalled".
  if (!ready) {
    return <ModuleLoadingState />;
  }
  const outcome = resolveModuleRoute(localModuleCatalog(), {
    hostScope,
    moduleKey,
    modulePath,
    companyId,
    ...access,
  });

  if (outcome.status === "module-unavailable") {
    return <ModuleUnavailableState moduleKey={outcome.moduleKey} />;
  }
  if (outcome.status === "route-not-found") {
    return <RouteNotFoundState moduleKey={outcome.moduleKey} modulePath={outcome.modulePath} />;
  }
  if (outcome.status === "access-denied") {
    return <AccessDeniedState moduleKey={outcome.moduleKey} featureKey={outcome.featureKey} />;
  }

  const registered = localModuleRegistry[outcome.module.moduleKey];
  const Page = registered?.pages[outcome.route.remoteExport];
  if (!Page) {
    // A catalog entry whose remoteExport has no registered component is itself a module-error,
    // not a resolver outcome — the resolver only knows about routing metadata, not the
    // component tree (modules/registry.ts's `pages` map).
    return <ModuleErrorState moduleKey={outcome.module.moduleKey} />;
  }

  const context = {
    moduleKey: outcome.module.moduleKey,
    companyId: outcome.companyId,
    featureKey: outcome.route.featureKey,
    params: outcome.params,
    remoteExport: outcome.route.remoteExport,
  };

  return (
    <ModuleErrorBoundary
      moduleKey={outcome.module.moduleKey}
      resetKey={modulePath}
      render={({ moduleKey: key, onRetry }) => <ModuleErrorState moduleKey={key} onRetry={onRetry} />}
    >
      <Suspense fallback={null}>
        <Page context={context} />
      </Suspense>
    </ModuleErrorBoundary>
  );
}
