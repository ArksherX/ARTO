import { Card, PageHeader, SampleBadge } from "../components/ui";

export default function Vestigia() {
  return (
    <>
      <PageHeader
        title="Vestigia · Audit ledger"
        sub={<><span className="text-ok">● Live</span><SampleBadge /></>}
      />
      <Card>
        <div className="font-display text-base font-bold">Audit ledger</div>
        <p className="mt-2 max-w-[70ch] text-[13.5px] text-muted">
          The hash-chain visualization, append-only event ledger and integrity/tamper panel
          get ported here and wired to the Vestigia API. Scaffolded — screen content lands in
          increment 4.
        </p>
      </Card>
    </>
  );
}
