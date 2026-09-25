// SPDX-License-Identifier: Apache-2.0

import { Navigate } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { useShellSession } from "../auth/session-context";
import { Alert, AlertDescription, AlertTitle } from "../ui/alert";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";

/** Same-origin, `/app`-rooted return-path sanitization (returnPath must be same-origin and start
 * with /app/ — the SDK deliberately leaves this to the host). */
function safeReturnPath(rawSearch: string): string | null {
  const params = new URLSearchParams(rawSearch);
  const returnPath = params.get("returnPath");
  if (!returnPath) return null;
  try {
    const url = new URL(returnPath, window.location.origin);
    if (url.origin !== window.location.origin || !url.pathname.startsWith("/app/")) {
      return null;
    }
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return null;
  }
}

export function CallbackPage() {
  const { handleCallback, session } = useShellSession();
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const started = useRef(false);

  // Defensive guard for anyone who lands on `/callback` without an OIDC response to
  // handle (old bookmarks, a stray direct navigation, or a Keycloak
  // RP-initiated-logout redirect). Neither `code` nor `error` present means there is nothing for
  // handleCallback() to do; redirect to `/` instead of invoking it and surfacing its "OIDC
  // callback URL is missing code and/or state" error.
  const params = new URLSearchParams(window.location.search);
  const hasNothingToHandle = !params.has("code") && !params.has("error");

  useEffect(() => {
    // React StrictMode double-invokes effects in dev; the SDK session's handleCallback is
    // idempotent for a given code, but guard here too so we do not fire two calls with
    // different closures over `started`.
    if (started.current) return;
    started.current = true;
    if (hasNothingToHandle) return;

    handleCallback(window.location.href)
      .then(() => setDone(true))
      .catch((err: unknown) => {
        // A full reload of `/callback?code=…` after the exchange already succeeded (the code is
        // consumed, the transaction is gone, but the persisted session is live) is not a failed
        // sign-in — the user is signed in; send them on instead of showing a raw error.
        if (session.isAuthenticated()) {
          setDone(true);
          return;
        }
        setError(err instanceof Error ? err.message : "Login failed");
      });
  }, [handleCallback, hasNothingToHandle, session]);

  if (hasNothingToHandle) {
    return <Navigate to="/" replace />;
  }

  if (done) {
    // `replace` so the consumed callback URL leaves the history: Back never lands on it.
    return <Navigate to={safeReturnPath(window.location.search) ?? "/app"} replace />;
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Completing sign in…</CardTitle>
        </CardHeader>
        <CardContent>
          {error ? (
            <Alert tone="red">
              <AlertTitle>Sign in failed</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : (
            <p className="text-sm text-muted-foreground">Please wait while we finish signing you in.</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
