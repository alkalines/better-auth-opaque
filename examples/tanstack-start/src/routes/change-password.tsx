import { createFileRoute } from "@tanstack/react-router";
import { authClient } from "../lib/auth-client";
import { fingerprint, loadDataKey, wrapDataKey } from "../lib/demo-crypto";
import { Status, errorText, field, useStatus } from "../lib/status";

export const Route = createFileRoute("/change-password")({ component: ChangePassword });

function ChangePassword() {
  const [status, setStatus] = useStatus();

  async function onSubmit(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;

    // The data key was stored on sign-in/sign-up in this tab; without it there is nothing to rewrap.
    const dataKey = await loadDataKey();
    if (!dataKey) {
      setStatus({ kind: "error", text: "Data key missing. Sign in again, then retry." });
      return;
    }

    setStatus({ kind: "working", text: "Changing password..." });
    const { data, error } = await authClient.opaque.changePassword({
      currentPassword: field(form, "currentPassword"),
      newPassword: field(form, "newPassword"),
      // Rewrap the same data key under the KEK of the new export key.
      payload: async (exportKey: string) => wrapDataKey(dataKey, exportKey),
    });

    if (error || !data) {
      setStatus({ kind: "error", text: errorText(error) });
      return;
    }

    setStatus({
      kind: "success",
      text: `Password changed. Key fingerprint: ${await fingerprint(dataKey)}`,
    });
  }

  return (
    <main>
      <h1>Change password</h1>
      <form id="change-password-form" onSubmit={onSubmit}>
        <label>
          Current password{" "}
          <input
            id="currentPassword"
            name="currentPassword"
            type="password"
            autoComplete="current-password"
            required
          />
        </label>
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
          Change password
        </button>
      </form>
      <Status status={status} />
    </main>
  );
}
