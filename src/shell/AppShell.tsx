import type { ReactNode } from "react";

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

export function AppShell({ section, onSelect, children }: AppShellProps) {
  const current = sectionById(section);
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
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <div className="topbar__left">
            <h1 className="topbar__title">{current.label}</h1>
            <p className="topbar__desc">{current.description}</p>
          </div>
          <ModeToggle />
        </header>
        <main className="content" id="main-content" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  );
}
