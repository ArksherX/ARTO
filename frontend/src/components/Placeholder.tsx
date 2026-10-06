import { Card, PageHeader } from "./ui";

// Navigable placeholder for a view that is mapped and backed by an endpoint but
// not yet ported from the Streamlit dashboard.
export default function Placeholder({ title, endpoint, note }: { title: string; endpoint?: string; note?: string }) {
  return (
    <>
      <PageHeader
        title={title}
        sub={<span className="rounded-md border border-dashed border-bd px-2 py-[3px] text-[11px] uppercase tracking-wider text-muted2">Porting in progress</span>}
      />
      <Card>
        <p className="max-w-[70ch] text-[13.5px] text-muted">
          This view is mapped for the new console{endpoint ? " and backed by " : "."}
          {endpoint && <code className="font-mono text-acc-300">{endpoint}</code>}
          {endpoint ? "." : ""} It's being ported from the Streamlit dashboard; the design
          language, routing and live-data pattern are already in place.
        </p>
        {note && <p className="mt-2 max-w-[70ch] text-[13px] text-muted2">{note}</p>}
      </Card>
    </>
  );
}
