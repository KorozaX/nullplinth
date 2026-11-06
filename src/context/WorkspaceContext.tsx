import { createContext, useCallback, useContext, useMemo, useState } from "react";
import type { ReactNode } from "react";

interface WorkspaceContextValue {
  version: number;
  refresh: () => void;
}

const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);

/** A monotonically increasing version that screens include in their loaders so
 * imports, clears and drag-and-drop refreshes reach every mounted screen. */
export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const [version, setVersion] = useState(0);
  const refresh = useCallback(() => setVersion((current) => current + 1), []);
  const value = useMemo<WorkspaceContextValue>(() => ({ version, refresh }), [version, refresh]);
  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

export function useWorkspace(): WorkspaceContextValue {
  const context = useContext(WorkspaceContext);
  if (!context) throw new Error("useWorkspace must be used inside WorkspaceProvider");
  return context;
}
