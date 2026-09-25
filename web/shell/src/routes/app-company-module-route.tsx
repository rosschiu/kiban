// SPDX-License-Identifier: Apache-2.0

// The company-scoped dynamic module route host (path `/app/c/$companyId/$module/$`).
import { ModuleRouteHost } from "./module-route-host";

export function AppCompanyModuleRoutePage({
  companyId,
  moduleKey,
  splat,
}: {
  companyId: string;
  moduleKey: string;
  splat?: string;
}) {
  return <ModuleRouteHost hostScope="company" companyId={companyId} moduleKey={moduleKey} modulePath={splat} />;
}
