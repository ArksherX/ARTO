export function LoadingLine({ show }: { show: boolean }) {
  if (!show) return null;
  return <p className="mb-3 text-[12px] text-muted2">Loading live data…</p>;
}

export function ErrorNote({ message }: { message: string }) {
  return (
    <div
      className="mb-3 rounded-[9px] border px-3 py-2.5 text-[12.5px]"
      style={{ color: "var(--high)", borderColor: "var(--high)", background: "color-mix(in srgb, var(--high) 12%, transparent)" }}
      role="alert"
    >
      {message}
    </div>
  );
}

export function EmptyRow({ cols, message }: { cols: number; message: string }) {
  return (
    <tr>
      <td colSpan={cols} className="py-7 text-center text-[12.5px] text-muted">
        {message}
      </td>
    </tr>
  );
}
