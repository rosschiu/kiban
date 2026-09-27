// SPDX-License-Identifier: Apache-2.0

// Pagination footer from the shared list toolkit. The Rows-per-page/Page controls use a plain
// native `<select>` styled to match the input/border tokens the other ui/*.tsx files use, rather
// than a shadcn `Select` primitive.
import type { ReactNode } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "./button";

interface ListPaginationFooterProps {
  currentPage: number;
  currentPageSize: number;
  isFetching?: boolean;
  pageSizeOptions: number[];
  summary: ReactNode;
  totalPages: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (pageSize: number) => void;
}

export function ListPaginationFooter({
  currentPage,
  currentPageSize,
  isFetching = false,
  pageSizeOptions,
  summary,
  totalPages,
  onPageChange,
  onPageSizeChange,
}: ListPaginationFooterProps) {
  const previousDisabled = currentPage <= 1 || isFetching;
  const nextDisabled = currentPage >= totalPages || isFetching;

  return (
    <>
      <div className="text-sm text-muted-foreground">{summary}</div>
      <div className="flex flex-wrap items-center gap-3 md:justify-end">
        <div className="flex items-center gap-2">
          <span className="text-sm text-muted-foreground">Rows per page</span>
          <select
            aria-label="Rows per page"
            className="h-8 rounded-md border border-input bg-background px-2 text-sm"
            value={currentPageSize}
            onChange={(event) => onPageSizeChange(Number(event.target.value))}
          >
            {pageSizeOptions.map((pageSize) => (
              <option key={pageSize} value={pageSize}>
                {pageSize}
              </option>
            ))}
          </select>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-sm text-muted-foreground">{`Page ${currentPage} of ${totalPages}`}</span>
          <Button type="button" variant="outline" size="sm" onClick={() => onPageChange(Math.max(1, currentPage - 1))} disabled={previousDisabled}>
            <ChevronLeft data-icon="inline-start" />
            Previous
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => onPageChange(Math.min(totalPages, currentPage + 1))}
            disabled={nextDisabled}
          >
            Next
            <ChevronRight data-icon="inline-end" />
          </Button>
        </div>
      </div>
    </>
  );
}
