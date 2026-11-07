import { useState } from "react";

export type StatusState = { kind: "idle" | "working" | "success" | "error"; text: string };

/** Visible status line shared by the demo forms; `data-state` is stable for browser tests. */
export function useStatus() {
  const [status, setStatus] = useState<StatusState>({ kind: "idle", text: "" });
  return [status, setStatus] as const;
}

export function Status({ status }: { status: StatusState }) {
  return (
    <p id="status" role="status" data-state={status.kind}>
      {status.text}
    </p>
  );
}

/** Reads a named text field from a submitted form. */
export function field(form: HTMLFormElement, name: string): string {
  return new FormData(form).get(name) as string;
}

export function errorText(error: { code?: string; message?: string } | null | undefined): string {
  return `${error?.code ?? "ERROR"}: ${error?.message ?? "Request failed"}`;
}
