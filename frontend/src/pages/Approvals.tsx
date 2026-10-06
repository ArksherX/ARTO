import Placeholder from "../components/Placeholder";

export default function Approvals() {
  return (
    <Placeholder
      title="Approvals"
      endpoint="/api/v1/approvals/pending · /{id}/decide"
      note="One global dual-control (four-eyes) queue across the suite — the requester cannot approve. Ported in the read/action pass."
    />
  );
}
