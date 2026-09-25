// SPDX-License-Identifier: Apache-2.0

// The global dynamic module route host (path `/app/$module/$`) — this file is exactly the
// component that path renders.
import { ModuleRouteHost } from "./module-route-host";

export function AppModuleRoutePage({ moduleKey, splat }: { moduleKey: string; splat?: string }) {
  return <ModuleRouteHost hostScope="global" moduleKey={moduleKey} modulePath={splat} />;
}
