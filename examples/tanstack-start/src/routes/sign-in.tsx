import { createFileRoute } from "@tanstack/react-router";
import { authClient } from "../lib/auth-client";
import { fingerprint, storeDataKey, unwrapDataKey } from "../lib/demo-crypto";
import { Status, errorText, field, useStatus } from "../lib/status";

export const Route = createFileRoute("/sign-in")({ component: SignIn });

function SignIn() {
  const [status, setStatus] = useStatus();

  async function onSubmit(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    setStatus({ kind: "working", text: "Signing in..." });

    const { data, error } = await authClient.signIn.opaque({
      email: field(form, "email"),
      password: field(form, "password"),
    });

    if (error || !data) {
      setStatus({ kind: "error", text: errorText(error) });
      return;
    }

    try {
      // The payload matches the credential that was just verified, so the export key unwraps it.
      const dataKey = await unwrapDataKey(data.payload, data.exportKey);
      await storeDataKey(dataKey);
      setStatus({
        kind: "success",
        text: `Signed in. Key fingerprint: ${await fingerprint(dataKey)}`,
      });
    } catch {
      setStatus({ kind: "error", text: "Signed in, but the payload could not be unwrapped." });
    }
  }

  return (
    <main>
      <h1>Sign in</h1>
      <form id="sign-in-form" onSubmit={onSubmit}>
        <label>
          Email <input id="email" name="email" type="email" autoComplete="email" required />
        </label>
        <label>
          Password{" "}
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
          />
        </label>
        <button type="submit" id="submit">
          Sign in
        </button>
      </form>
      <Status status={status} />
    </main>
  );
}
