// SPDX-License-Identifier: Apache-2.0

// Table shell from the shared list toolkit.
import type { ReactNode } from "react";
import { cn } from "./cn";

interface ListTableShellProps {
  className?: string;
  emptyState: ReactNode;
  footer?: ReactNode;
  isEmpty: boolean;
  isLoading?: boolean;
  tableContent: ReactNode;
}

export function ListTableShell({ className, emptyState, footer, isEmpty, isLoading = false, tableContent }: ListTableShellProps) {
  return (
    <div className={cn("flex flex-col rounded-md border md:min-h-0 md:flex-1 md:overflow-hidden", className)}>
      <div className="overflow-auto md:min-h-0 md:flex-1">{isEmpty && !isLoading ? emptyState : tableContent}</div>
      {footer ? (
        <div className="flex flex-col gap-3 border-t px-4 py-3 md:flex-row md:items-center md:justify-between">{footer}</div>
      ) : null}
    </div>
  );
}
