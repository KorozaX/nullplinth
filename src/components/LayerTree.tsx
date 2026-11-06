import { Fragment } from "react";

import type { LayerNode } from "../types/contracts";

function LayerBranch({ node, depth }: { node: LayerNode; depth: number }) {
  return (
    <details className="layer" open={depth < 2}>
      <summary className="layer__head">
        <span>{node.label}</span>
        <span className="layer__kind">{node.name}</span>
      </summary>
      {node.fields.length > 0 ? (
        <div className="layer__fields">
          {node.fields.map((field, index) => (
            <Fragment key={field.name + "-" + String(index)}>
              <span className="layer__key">{field.name}</span>
              <span className="layer__val">{field.value}</span>
            </Fragment>
          ))}
        </div>
      ) : null}
      {node.children.length > 0 ? (
        <div className="layer__children">
          {node.children.map((child, index) => (
            <LayerBranch key={child.name + "-" + String(index)} node={child} depth={depth + 1} />
          ))}
        </div>
      ) : null}
    </details>
  );
}

export function LayerTree({ layers }: { layers: readonly LayerNode[] }) {
  if (layers.length === 0) return <p className="muted">No decoded layers for this packet.</p>;
  return (
    <div className="layer-tree">
      {layers.map((node, index) => (
        <LayerBranch key={node.name + "-" + String(index)} node={node} depth={0} />
      ))}
    </div>
  );
}
