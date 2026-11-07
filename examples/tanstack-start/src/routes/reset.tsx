import { createFileRoute } from "@tanstack/react-router";
import { useEffect } from "react";
import { authClient } from "../lib/auth-client";
import { fingerprint, generateDataKey, storeDataKey, wrapDataKey } from "../lib/demo-crypto";
import { Status, errorText, field, useStatus } from "../lib/status";

export const Route = createFileRoute("/reset")({
  validateSearch: (search: Record<string, unknown>) => ({
    token: typeof search.token === "string" ? search.token : "",
  }),
  component: Reset,
});

function Reset() {
  const { token } = Route.useSearch();
  const [status, setStatus] = useStatus();

  // Checking the token does not consume it; the challenge step below does.
  useEffect(() => {
    let cancelled = false;
    setStatus({ kind: "working", text: "Checking reset token..." });
    void authClient.opaque.verifyResetToken({ token }).then(({ error }) => {
      if (cancelled) {
        return;
      }
      setStatus(
        error
          ? { kind: "error", text: errorText(error) }
          : { kind: "idle", text: "Reset token is valid." },
      );
    });
    return () => {
      cancelled = true;
    };
  }, [token, setStatus]);

  async function onSubmit(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    setStatus({ kind: "working", text: "Resetting password..." });

    // The old data key is unrecoverable without the old password, so this demo starts a new one.
    const dataKey = await generateDataKey();
    const { data, error } = await authClient.opaque.resetPassword({
      token,
      newPassword: field(form, "newPassword"),
      payload: async (exportKey: string) => wrapDataKey(dataKey, exportKey),
    });

    if (error || !data) {
      setStatus({ kind: "error", text: errorText(error) });
      return;
    }

    await storeDataKey(dataKey);
    setStatus({
      kind: "success",
      text: `Password reset. New key fingerprint: ${await fingerprint(dataKey)}`,
    });
  }

  return (
    <main>
      <h1>Reset password</h1>
      <form id="reset-form" onSubmit={onSubmit}>
        <input id="token" name="token" type="hidden" value={token} readOnly />
        <label>
          New password{" "}
          <input
            id="newPassword"
            name="newPassword"
            type="password"
            autoComplete="new-password"
            minLength={8}
            required
          />
        </label>
        <button type="submit" id="submit">
          Reset password
        </button>
      </form>
      <Status status={status} />
    </main>
  );
}
