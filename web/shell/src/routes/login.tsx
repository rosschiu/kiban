// SPDX-License-Identifier: Apache-2.0

// 50/50 split login: auth column
// (max-w-sm) on the left, cover on the right, mobile hero strip with a scrim + backdrop-blur
// title. Keeps Kiban's designed callback/failure states (routes/states.tsx, routes/callback.tsx)
// untouched.
//
// The cover is a neutral gradient rather than an image asset (no image with verified
// licensing/attribution is shipped).
import { useShellSession } from "../auth/session-context";
import { Button } from "../ui/button";

export function LoginPage() {
  const { login } = useShellSession();

  return (
    <main className="grid min-h-svh bg-background text-foreground lg:h-svh lg:grid-cols-2 lg:overflow-hidden" data-testid="login-shell">
      <section className="order-2 flex items-start justify-center bg-background px-6 py-8 lg:order-1 lg:h-svh lg:overflow-y-auto lg:px-10 lg:py-12">
        <div className="w-full max-w-sm space-y-6 lg:my-auto">
          <header className="space-y-2">
            <p className="text-sm font-extrabold uppercase tracking-[0.24em] text-primary">Kiban Platform</p>
            <h1 className="text-3xl font-bold tracking-[-0.04em] text-foreground">Sign in to Kiban</h1>
            <p className="text-sm text-muted-foreground">You will be redirected to the platform&apos;s identity provider.</p>
          </header>
          <Button type="button" className="h-11 w-full" onClick={() => void login()}>
            Log in
          </Button>
        </div>
      </section>
      <aside
        className="relative order-1 h-[clamp(11.5rem,30svh,14.5rem)] overflow-hidden bg-sidebar-primary lg:order-2 lg:h-svh"
        aria-hidden="true"
      >
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,color-mix(in_oklab,var(--sidebar-primary)_70%,white),var(--sidebar-primary)_60%)]" />
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_48%,rgba(2,6,23,0.42),rgba(2,6,23,0.08)_68%),linear-gradient(180deg,rgba(2,6,23,0.45),rgba(2,6,23,0.08))] lg:hidden" />
        <div className="absolute inset-0 flex items-center justify-center px-5 text-center text-white">
          <div className="max-w-md rounded-2xl bg-slate-950/25 px-4 py-3 backdrop-blur-[1px]">
            <p className="text-sm font-extrabold uppercase tracking-[0.24em]">Kiban Platform</p>
            <p className="mt-1 text-2xl font-bold tracking-[-0.04em]">Modular back-office, one platform</p>
          </div>
        </div>
      </aside>
    </main>
  );
}
