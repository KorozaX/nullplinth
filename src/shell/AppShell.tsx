import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { Maximize2, Minimize2, Search } from "lucide-react";

import { useMode } from "../context/ModeContext";
import { MODE_OPTIONS } from "../lib/mode";
import { cx } from "../lib/cx";
import { IconButton } from "../components/ui/Button";
import { Tooltip } from "../components/ui/Tooltip";
import { SECTIONS, sectionById } from "./sections";
import type { SectionId } from "./sections";

export function ModeToggle() {
  const { mode, setMode } = useMode();
  return (
    <div className="mode-switch" role="group" aria-label="Experience mode">
      {MODE_OPTIONS.map((option) => (
        <button
          key={option.value}
          type="button"
          className={cx("mode-switch__btn", mode === option.value && "is-active")}
          aria-pressed={mode === option.value}
          title={option.hint}
          onClick={() => setMode(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

export interface AppShellProps {
  section: SectionId;
  onSelect: (next: SectionId) => void;
  children: ReactNode;
  /** Mono summary of the active workspace, shown in the top bar. */
  workspaceSummary?: string;
  /** Global search entry point; receives the query when the user presses Enter. */
  onSearch?: (text: string) => void;
}

function tauriWindow() {
  if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) return null;
  return import("@tauri-apps/api/window").then((m) => m.getCurrentWindow());
}

async function toggleFullscreen(): Promise<boolean> {
  const win = await tauriWindow();
  if (!win) return false;
  const next = !(await win.isFullscreen());
  await win.setFullscreen(next);
  return next;
}

export function AppShell({ section, onSelect, children, workspaceSummary, onSearch }: AppShellProps) {
  const current = sectionById(section);
  const { mode, setMode } = useMode();
  const [fullscreen, setFullscreen] = useState(false);
  const [query, setQuery] = useState("");

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "F11") {
        event.preventDefault();
        void toggleFullscreen().then(setFullscreen);
        return;
      }
      if (!event.altKey || event.ctrlKey || event.metaKey) return;
      const index = Number(event.key);
      if (index >= 1 && index <= SECTIONS.length) {
        event.preventDefault();
        onSelect(SECTIONS[index - 1].id);
      } else if (event.key.toLowerCase() === "m") {
        event.preventDefault();
        setMode(mode === "analyst" ? "beginner" : "analyst");
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [mode, onSelect, setMode]);

  function submitSearch() {
    const text = query.trim();
    if (text.length === 0 || !onSearch) return;
    onSearch(text);
    setQuery("");
  }

  return (
    <div className="shell">
      <aside className="rail">
        <div className="rail__brand" aria-hidden="true">
          N
        </div>

        <nav className="rail__nav" aria-label="Sections">
          <ul className="rail__list">
            {SECTIONS.map((entry) => {
              const Icon = entry.icon;
              const active = entry.id === section;
              return (
                <li key={entry.id}>
                  <Tooltip label={entry.label}>
                    <button
                      type="button"
                      className={cx("rail__item", active && "is-active")}
                      aria-label={entry.label}
                      aria-current={active ? "page" : undefined}
                      onClick={() => onSelect(entry.id)}
                    >
                      <Icon size={17} aria-hidden="true" />
                    </button>
                  </Tooltip>
                </li>
              );
            })}
          </ul>
        </nav>

        <div className="rail__foot">
          <Tooltip label="Local only · no network access">
            <span className="rail__status" aria-hidden="true" />
          </Tooltip>
          <span className="rail__version">v0.3.0</span>
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <div className="topbar__left">
            <h1 className="topbar__title">{current.label}</h1>
            {workspaceSummary ? (
              <p className="topbar__meta" title={workspaceSummary}>
                {workspaceSummary}
              </p>
            ) : null}
          </div>

          <div className="topbar__actions">
            <div className="search-field">
              <Search size={13} aria-hidden="true" />
              <input
                type="search"
                aria-label="Global search"
                placeholder="Search events"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") submitSearch();
                }}
              />
              <kbd>Enter</kbd>
            </div>
            <IconButton
              icon={fullscreen ? Minimize2 : Maximize2}
              label={fullscreen ? "Exit fullscreen (F11)" : "Enter fullscreen (F11)"}
              onClick={() => void toggleFullscreen().then(setFullscreen)}
            />
            <ModeToggle />
          </div>
        </header>
        <main className="content" id="main-content" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  );
}