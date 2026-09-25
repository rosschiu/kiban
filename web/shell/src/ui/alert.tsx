// SPDX-License-Identifier: Apache-2.0

import { cva, type VariantProps } from "class-variance-authority";
import { type HTMLAttributes, forwardRef } from "react";
import { cn } from "./cn";

// The toast/alert color grammar: "red=failure
// amber=warning/company-required/one-time-secret sky=in-progress emerald=success". Named `tone`
// rather than shadcn's default two-variant Alert so all four are first-class, not bolted on.
const alertVariants = cva("relative w-full rounded-lg border p-4 text-sm [&>svg]:size-4", {
  variants: {
    tone: {
      neutral: "border-border bg-card text-card-foreground",
      red: "border-red-200 bg-red-50 text-red-800 dark:border-red-900/50 dark:bg-red-950/40 dark:text-red-200",
      amber: "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-900/50 dark:bg-amber-950/40 dark:text-amber-200",
      sky: "border-sky-200 bg-sky-50 text-sky-800 dark:border-sky-900/50 dark:bg-sky-950/40 dark:text-sky-200",
      emerald: "border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-900/50 dark:bg-emerald-950/40 dark:text-emerald-200",
    },
  },
  defaultVariants: { tone: "neutral" },
});

export interface AlertProps extends HTMLAttributes<HTMLDivElement>, VariantProps<typeof alertVariants> {}

export const Alert = forwardRef<HTMLDivElement, AlertProps>(function Alert({ className, tone, ...props }, ref) {
  return <div ref={ref} role="alert" data-slot="alert" data-tone={tone ?? "neutral"} className={cn(alertVariants({ tone }), className)} {...props} />;
});

export function AlertTitle({ className, ...props }: HTMLAttributes<HTMLHeadingElement>) {
  return <h5 data-slot="alert-title" className={cn("mb-1 font-medium leading-none tracking-tight", className)} {...props} />;
}

export function AlertDescription({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div data-slot="alert-description" className={cn("text-sm opacity-90 [&_p]:leading-relaxed", className)} {...props} />;
}
