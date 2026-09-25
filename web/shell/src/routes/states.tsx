// SPDX-License-Identifier: Apache-2.0

// The four distinct, designed module-route failure states (module-unavailable / route-not-found /
// access-denied / module-error — DISTINCT, designed states a human will see). Three map directly
// to resolver.ts's ModuleRouteOutcome
// statuses; "module-error" is a fourth, UI-only state for when a resolved module's lazy
// component itself throws/fails to load (an error boundary condition the resolver never sees,
// since the resolver is pure and never touches the component tree).
import { CompassIcon, PackageXIcon, ShieldAlertIcon, TriangleAlertIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Button } from "../ui/button";
import { cn } from "../ui/cn";

function StatePage({
  tone,
  icon,
  title,
  children,
  action,
}: {
  tone: "amber" | "sky" | "red";
  icon: ReactNode;
  title: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex min-h-[60vh] flex-1 items-center justify-center p-6">
      <div className="w-full max-w-md text-center">
        <div
          className={cn(
            "mx-auto mb-4 flex size-14 items-center justify-center rounded-full",
            tone === "amber" && "bg-amber-100 text-amber-700 dark:bg-amber-950/50 dark:text-amber-300",
            tone === "sky" && "bg-sky-100 text-sky-700 dark:bg-sky-950/50 dark:text-sky-300",
            tone === "red" && "bg-red-100 text-red-700 dark:bg-red-950/50 dark:text-red-300",
          )}
        >
          {icon}
        </div>
        <h1 className="text-lg font-semibold text-foreground">{title}</h1>
        <p className="mt-2 text-sm text-muted-foreground">{children}</p>
        {action ? <div className="mt-6">{action}</div> : null}
      </div>
    </div>
  );
}

export function ModuleUnavailableState({ moduleKey }: { moduleKey: string }) {
  return (
    <StatePage tone="amber" icon={<PackageXIcon className="size-6" aria-hidden="true" />} title="Module unavailable">
      <>
        <code className="rounded bg-muted px-1 py-0.5 text-xs">{moduleKey}</code> is not enabled for this Kiban instance, or
        your account cannot use it.
      </>
    </StatePage>
  );
}

export function RouteNotFoundState({ moduleKey, modulePath }: { moduleKey: string; modulePath: string }) {
  return (
    <StatePage tone="sky" icon={<CompassIcon className="size-6" aria-hidden="true" />} title="Page not found in this module">
      <>
        The <code className="rounded bg-muted px-1 py-0.5 text-xs">{moduleKey}</code> module does not publish a page at{" "}
        <code className="rounded bg-muted px-1 py-0.5 text-xs">{modulePath}</code>.
      </>
    </StatePage>
  );
}

export function AccessDeniedState({ moduleKey, featureKey }: { moduleKey: string; featureKey: string }) {
  return (
    <StatePage tone="red" icon={<ShieldAlertIcon className="size-6" aria-hidden="true" />} title="Access denied">
      <>
        You do not have the <code className="rounded bg-muted px-1 py-0.5 text-xs">{featureKey}</code> permission needed to
        open this page of <code className="rounded bg-muted px-1 py-0.5 text-xs">{moduleKey}</code>.
      </>
    </StatePage>
  );
}

export function ModuleErrorState({ moduleKey, onRetry }: { moduleKey: string; onRetry?: () => void }) {
  return (
    <StatePage
      tone="red"
      icon={<TriangleAlertIcon className="size-6" aria-hidden="true" />}
      title="Module failed to load"
      action={
        onRetry ? (
          <Button type="button" variant="outline" size="sm" onClick={onRetry}>
            Try again
          </Button>
        ) : undefined
      }
    >
      <>
        Something went wrong while loading <code className="rounded bg-muted px-1 py-0.5 text-xs">{moduleKey}</code>. This is
        a module-side error, not a permissions problem.
      </>
    </StatePage>
  );
}

/** Neutral pending state: rendered while the session's platform composition is
 * still loading — deliberately quiet (no icon medallion, no failure copy), because "still
 * checking" must never look like "module unavailable". */
export function ModuleLoadingState() {
  return (
    <div data-testid="module-loading" aria-busy="true" className="flex flex-col gap-3 p-6">
      <div className="h-6 w-48 animate-pulse rounded-md bg-muted" />
      <div className="h-4 w-72 animate-pulse rounded-md bg-muted" />
      <div className="h-4 w-64 animate-pulse rounded-md bg-muted" />
    </div>
  );
}
