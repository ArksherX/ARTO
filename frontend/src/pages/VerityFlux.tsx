import { Card, PageHeader, SampleBadge } from "../components/ui";

export default function VerityFlux() {
  return (
    <>
      <PageHeader
        title="VerityFlux · Runtime detection"
        sub={<><span className="text-ok">● Live</span><SampleBadge /></>}
      />
      <Card>
        <div className="font-display text-base font-bold">Runtime monitoring</div>
        <p className="mt-2 max-w-[70ch] text-[13.5px] text-muted">
          Detection stream, session crescendo trajectory, intent mix and the requires-review
          queue get ported here and wired to the VerityFlux API. Scaffolded — screen content
          lands in increment 3. The design reference is the prototype in this session.
        </p>
      </Card>
    </>
  );
}
