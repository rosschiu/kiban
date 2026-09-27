// SPDX-License-Identifier: Apache-2.0

// Site header. No "use client" directive (Next.js-only; this is a Vite SPA).
import { Fragment, type ReactNode } from "react";
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "./breadcrumb";
import { Separator } from "./separator";
import { SidebarTrigger } from "./sidebar";

type BreadcrumbItemData = {
  label: string;
  href?: string;
};

type SiteHeaderProps = {
  items: BreadcrumbItemData[];
  actions?: ReactNode;
};

export function SiteHeader({ items, actions }: SiteHeaderProps) {
  return (
    <header data-slot="site-header" className="sticky top-0 z-40 flex h-16 shrink-0 items-center border-b bg-background">
      <div className="flex w-full items-center gap-2 px-4">
        <div className="flex min-w-0 flex-1 items-center gap-2">
          <SidebarTrigger className="-ml-1" />
          <Separator orientation="vertical" className="mr-2 data-[orientation=vertical]:h-4" />
          <Breadcrumb className="hidden min-w-0 sm:block">
            <BreadcrumbList>
              {items.map((item, index) => (
                <Fragment key={`${item.href ?? item.label}-${index}`}>
                  <BreadcrumbItem>
                    {item.href ? (
                      <BreadcrumbLink href={item.href}>{item.label}</BreadcrumbLink>
                    ) : (
                      <BreadcrumbPage>{item.label}</BreadcrumbPage>
                    )}
                  </BreadcrumbItem>
                  {index < items.length - 1 && <BreadcrumbSeparator />}
                </Fragment>
              ))}
            </BreadcrumbList>
          </Breadcrumb>
        </div>
        {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
      </div>
    </header>
  );
}
