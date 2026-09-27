// SPDX-License-Identifier: Apache-2.0

// Route tree assembly. Routes are assembled here with TanStack Router's code-based API rather
// than the `@tanstack/router-plugin` file-based codegen — the plugin's generated
// `routeTree.gen.ts` buys nothing for a route tree this small and would add a codegen step to
// `npm run -w shell test`/`build` for no behavioral difference. Each route component lives in
// its own file under routes/, named after the path it renders.
import { Navigate, Outlet, createRootRoute, createRoute, createRouter } from "@tanstack/react-router";
import { useShellSession } from "./auth/session-context";
import { AdminGroupsPage } from "./routes/admin-groups-page";
import { AdminPositionsPage } from "./routes/admin-positions-page";
import { AppCompanyModuleRoutePage } from "./routes/app-company-module-route";
import { AppDashboardPage } from "./routes/app-dashboard";
import { AppModuleRoutePage } from "./routes/app-module-route";
import { CallbackPage } from "./routes/callback";
import { GuardedRoot } from "./routes/guarded-root";
import { LoginPage } from "./routes/login";

const rootRoute = createRootRoute({ component: Outlet });

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: function IndexRedirect() {
    const { isAuthenticated } = useShellSession();
    return <Navigate to={isAuthenticated ? "/app" : "/login"} />;
  },
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  component: function LoginRoute() {
    const { isAuthenticated } = useShellSession();
    if (isAuthenticated) return <Navigate to="/app" />;
    return <LoginPage />;
  },
});

const callbackRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/callback",
  component: CallbackPage,
});

const appLayoutRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/app",
  component: GuardedRoot,
});

const appIndexRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/",
  component: AppDashboardPage,
});

// The sample shell's minimal position-based-access admin surface
// — a static route, registered ahead of the dynamic `$module/$` catch-all below so
// `/app/admin/positions` never gets swallowed by it (TanStack Router ranks static segments over
// dynamic params regardless of addChildren order, but the ordering here documents the intent).
// Reachability is nav-gated only (nav/compose.ts's computeNavEntries appends this entry only
// when the caller's global summary carries `auth.platform_administration.access`); the page and
// every API call it makes are independently superadmin-guarded regardless of how the URL is
// reached.
const appAdminPositionsRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "admin/positions",
  component: AdminPositionsPage,
});

// The Groups admin page — same static-route, nav-gated-only posture as Positions above.
const appAdminGroupsRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "admin/groups",
  component: AdminGroupsPage,
});

const appModuleRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "$module/$",
  component: function AppModuleRouteComponent() {
    const { module, _splat } = appModuleRoute.useParams();
    return <AppModuleRoutePage moduleKey={module} splat={_splat} />;
  },
});

const appCompanyModuleRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "c/$companyId/$module/$",
  component: function AppCompanyModuleRouteComponent() {
    const { companyId, module, _splat } = appCompanyModuleRoute.useParams();
    return <AppCompanyModuleRoutePage companyId={companyId} moduleKey={module} splat={_splat} />;
  },
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  loginRoute,
  callbackRoute,
  appLayoutRoute.addChildren([appIndexRoute, appAdminPositionsRoute, appAdminGroupsRoute, appModuleRoute, appCompanyModuleRoute]),
]);

export function createShellRouter() {
  return createRouter({ routeTree, defaultPreload: "intent" });
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof createShellRouter>;
  }
}
