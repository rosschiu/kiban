// SPDX-License-Identifier: Apache-2.0

import { Component, type ReactNode } from "react";

interface ModuleErrorBoundaryProps {
  moduleKey: string;
  /** Bumping this remounts the boundary (used by the "Try again" action). */
  resetKey?: unknown;
  render: (args: { moduleKey: string; onRetry: () => void }) => ReactNode;
  children: ReactNode;
}

interface ModuleErrorBoundaryState {
  error: unknown;
}

/** Catches a lazy module component's render/load failure and renders the module-error state
 * instead of crashing the whole shell (the 4th designed failure state,
 * distinct from the resolver's 3 outcomes since the resolver never touches the component tree). */
export class ModuleErrorBoundary extends Component<ModuleErrorBoundaryProps, ModuleErrorBoundaryState> {
  state: ModuleErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: unknown): ModuleErrorBoundaryState {
    return { error };
  }

  private reset = (): void => {
    this.setState({ error: null });
  };

  render(): ReactNode {
    if (this.state.error) {
      return this.props.render({ moduleKey: this.props.moduleKey, onRetry: this.reset });
    }
    return this.props.children;
  }
}
