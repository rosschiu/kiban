// SPDX-License-Identifier: Apache-2.0

import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** shadcn/ui's canonical class-merge helper — the single `cn` implementation in this codebase. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
