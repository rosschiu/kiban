// SPDX-License-Identifier: Apache-2.0

import type { LucideIcon } from "lucide-react";
import { Inbox } from "lucide-react";
import type { ReactNode } from "react";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "./empty";

export interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description?: ReactNode;
  className?: string;
}

/** Shared empty-state primitive, built on ui/empty.tsx's compound primitives. Used both by the
 * sidebar's empty-catalog state and by module page bodies. */
export function EmptyState({ icon: Icon = Inbox, title, description, className }: EmptyStateProps) {
  return (
    <Empty data-slot="empty-state" className={className}>
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <Icon aria-hidden="true" />
        </EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        {description ? <EmptyDescription>{description}</EmptyDescription> : null}
      </EmptyHeader>
    </Empty>
  );
}
