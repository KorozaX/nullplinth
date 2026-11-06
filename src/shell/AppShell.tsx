import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { Maximize2, Minimize2 } from "lucide-react";

import { useMode } from "../context/ModeContext";
import { MODE_OPTIONS } from "../lib/mode";
import { cx } from "../lib/cx";
import { SECTIONS, sectionById } from "./sections";
import type { SectionId } from "./sections";

export function ModeToggle() {
  const { mode, setMode } = useMode();
  return (
    <div className="mode-toggle" role="group" aria-label="Experience mode">
      {MODE_OPTIONS.map((option) => (
        <button
          key={option.value}
          type="button"
          className={cx("mode-toggle__btn", mode === option.value && "is-active")}
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

export function AppShell({ section, onSelect, children }: AppShellProps) {
  const current = sectionById(section);
  const { mode, setMode } = useMode();
  const [fullscreen, setFullscreen] = useState(false);

  // Analyst-mode shortcuts: F11 fullscreen, Alt+1..7 jump to a section, Alt+M switches mode.
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

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand__mark" aria-hidden="true">
            N
          </span>
          <div className="brand__text">
            <span className="brand__name">NULLPLINTH</span>
            <span className="brand__tag">Local analysis workbench</span>
          </div>
        </div>

        <nav className="nav" aria-label="Sections">
          <ul className="nav__list">
            {SECTIONS.map((entry) => {
              const Icon = entry.icon;
              const active = entry.id === section;
              return (
                <li key={entry.id}>
                  <button
                    type="button"
                    className={cx("nav__item", active && "is-active")}
                    aria-current={active ? "page" : undefined}
                    onClick={() => onSelect(entry.id)}
                  >
                    <Icon size={15} aria-hidden="true" />
                    <span>{entry.label}</span>
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>

        <div className="sidebar__foot">
          <strong>Local only</strong>
          <span>No network access</span>
          <span>v0.1.0</span>
          <span className="sidebar__hint">Alt+1..7 sections &middot; Alt+M mode &middot; F11 fullscreen</span>
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <div className="topbar__left">
            <h1 className="topbar__title">{current.label}</h1>
            <p className="topbar__desc">{current.description}</p>
          </div>
          <div className="topbar__actions">
            <button
              type="button"
              className="icon-btn"
              aria-label={fullscreen ? "Exit fullscreen (F11)" : "Enter fullscreen (F11)"}
              title={fullscreen ? "Exit fullscreen (F11)" : "Enter fullscreen (F11)"}
              onClick={() => void toggleFullscreen().then(setFullscreen)}
            >
              {fullscreen ? <Minimize2 size={14} aria-hidden="true" /> : <Maximize2 size={14} aria-hidden="true" />}
            </button>
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