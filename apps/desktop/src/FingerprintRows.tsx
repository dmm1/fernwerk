// Label/value list for host key details, shared by the trust prompt and the fingerprint check.
import { Fragment } from "react";

export function FingerprintRows({ rows }: { rows: [string, string][] }) {
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-xs break-all">
      {rows.map(([label, value]) => (
        <Fragment key={label}>
          <dt className="text-foreground-dim">{label}</dt>
          <dd>{value}</dd>
        </Fragment>
      ))}
    </dl>
  );
}
