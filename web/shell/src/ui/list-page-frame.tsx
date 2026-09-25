// SPDX-License-Identifier: Apache-2.0

// List page frame from the shared list toolkit (ListPageFrame/ListTableShell/
// ListPaginationFooter), styled with the shadcn/Slate tokens.
import type { ReactNode } from "react";

interface ListPageFrameProps {
  children: ReactNode;
  desktopFilters?: ReactNode;
  error?: ReactNode;
  headerActions?: ReactNode;
  title: string;
}

export function ListPageFrame({ children, desktopFilters, error, headerActions, title }: ListPageFrameProps) {
  return (
    <div className="flex min-h-full flex-col gap-6 overflow-y-auto md:h-full md:min-h-0 md:overflow-hidden">
      <div className="flex shrink-0 flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="space-y-1.5">
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        </div>
        {headerActions ? headerActions : null}
      </div>

      {error ? error : null}
      {desktopFilters ? desktopFilters : null}
      {children}
    </div>
  );
}
