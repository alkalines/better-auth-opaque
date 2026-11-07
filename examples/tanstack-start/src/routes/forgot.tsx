import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Status, field, useStatus } from "../lib/status";

export const Route = createFileRoute("/forgot")({ component: Forgot });

/**
 * Dev stand-in for the reset email: asks the localhost-only dev route for the reset URL and shows
 * it as a link. A real app would email the URL returned by `auth.api.createPasswordResetToken`.
 */
function Forgot() {
  const [status, setStatus] = useStatus();
  const [resetUrl, setResetUrl] = useState<string | null>(null);

  async function onSubmit(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    setStatus({ kind: "working", text: "Requesting reset link..." });
    setResetUrl(null);

    const response = await fetch("/api/dev/reset-token", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: field(event.currentTarget, "email") }),
    });
    const body = (await response.json()) as { url?: string; error?: string };

    if (!response.ok || !body.url) {
      setStatus({ kind: "error", text: body.error ?? "Request failed" });
      return;
    }

    setResetUrl(body.url);
    setStatus({ kind: "success", text: "Reset link created." });
  }

  return (
    <main>
      <h1>Forgot password</h1>
      <form id="forgot-form" onSubmit={onSubmit}>
        <label>
          Email <input id="email" name="email" type="email" autoComplete="email" required />
        </label>
        <button type="submit" id="submit">
          Create reset link
        </button>
      </form>
      <Status status={status} />
      {resetUrl ? (
        <p>
          <a id="reset-link" href={resetUrl}>
            {resetUrl}
          </a>
        </p>
      ) : null}
    </main>
  );
}
