import { Card, PageHeader, SampleBadge } from "../components/ui";

export default function Tessera() {
  return (
    <>
      <PageHeader
        title="Tessera · Identity & delegation"
        sub={<><span className="text-ok">● Live</span><SampleBadge /></>}
      />
      <Card>
        <div className="font-display text-base font-bold">Identity & delegation</div>
        <p className="mt-2 max-w-[70ch] text-[13.5px] text-muted">
          The delegation chain (scope attenuation + denied escalation), agent registry and
          dual-control approval queue get ported here and wired to the Tessera API. Scaffolded
          — screen content lands in increment 5.
        </p>
      </Card>
    </>
  );
}
