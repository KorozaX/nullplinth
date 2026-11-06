import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { isMode, MODE_STORAGE_KEY } from "../lib/mode";
import type { Mode } from "../lib/mode";

interface ModeContextValue {
  mode: Mode;
  setMode: (next: Mode) => void;
  toggleMode: () => void;
  isAnalyst: boolean;
}

const ModeContext = createContext<ModeContextValue | null>(null);

function readStoredMode(): Mode {
  try {
    const stored = window.localStorage.getItem(MODE_STORAGE_KEY);
    return isMode(stored) ? stored : "analyst";
  } catch {
    return "analyst";
  }
}

export function ModeProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<Mode>(readStoredMode);

  useEffect(() => {
    try {
      window.localStorage.setItem(MODE_STORAGE_KEY, mode);
    } catch {
      // Storage can be unavailable; the mode still applies for this session.
    }
  }, [mode]);

  const setMode = useCallback((next: Mode) => setModeState(next), []);
  const toggleMode = useCallback(
    () => setModeState((current) => (current === "analyst" ? "beginner" : "analyst")),
    [],
  );

  const value = useMemo<ModeContextValue>(
    () => ({ mode, setMode, toggleMode, isAnalyst: mode === "analyst" }),
    [mode, setMode, toggleMode],
  );

  return <ModeContext.Provider value={value}>{children}</ModeContext.Provider>;
}

export function useMode(): ModeContextValue {
  const context = useContext(ModeContext);
  if (!context) throw new Error("useMode must be used inside ModeProvider");
  return context;
}
