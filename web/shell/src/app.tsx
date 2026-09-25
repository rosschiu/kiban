// SPDX-License-Identifier: Apache-2.0

import { RouterProvider } from "@tanstack/react-router";
import { useMemo } from "react";
import { ShellSessionProvider } from "./auth/session-context";
import { CompanyContextProvider } from "./nav/company-context";
import { createShellRouter } from "./router";

export function App() {
  const router = useMemo(() => createShellRouter(), []);

  return (
    <ShellSessionProvider>
      <CompanyContextProvider>
        <RouterProvider router={router} />
      </CompanyContextProvider>
    </ShellSessionProvider>
  );
}
