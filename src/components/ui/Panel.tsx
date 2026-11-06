import type { ReactNode } from "react";

import { cx } from "../../lib/cx";

export interface PanelProps {
  title?: ReactNode;
  meta?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  flush?: boolean;
}

export function Panel({ title, meta, actions, children, className, bodyClassName, flush }: PanelProps) {
  const showHead = title !== undefined || meta !== undefined || actions !== undefined;
  return (
    <section className={cx("panel", className)}>
      {showHead ? (
        <header className="panel__head">
          <div className="panel__heading">
            {title !== undefined ? <h2 className="panel__title">{title}</h2> : null}
            {meta !== undefined ? <span className="panel__meta">{meta}</span> : null}
          </div>
          {actions !== undefined ? <div className="panel__actions">{actions}</div> : null}
        </header>
      ) : null}
      <div className={cx("panel__body", flush && "panel__body--flush", bodyClassName)}>{children}</div>
    </section>
  );
}

export function Subhead({ children }: { children: ReactNode }) {
  return <h3 className="subhead">{children}</h3>;
}
