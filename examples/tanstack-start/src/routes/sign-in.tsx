import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { authClient } from "../lib/auth-client";
import { fingerprint, storeDataKey, unwrapDataKey } from "../lib/demo-crypto";
import { Status, errorText, field, useStatus } from "../lib/status";

export const Route = createFileRoute("/sign-in")({ component: SignIn });

function SignIn() {
  const [status, setStatus] = useStatus();
  // Keep these client secrets in memory until the second factor establishes a session.
  const [pending, setPending] = useState<{ exportKey: string; payloadToken: string } | null>(null);

  async function finishSignIn(payload: unknown, exportKey: string) {
    try {
      const dataKey = await unwrapDataKey(payload, exportKey);
      await storeDataKey(dataKey);
      setStatus({
        kind: "success",
        text: `Signed in. Key fingerprint: ${await fingerprint(dataKey)}`,
      });
    } catch {
      setStatus({ kind: "error", text: "Signed in, but the payload could not be unwrapped." });
    }
  }

  async function onSubmit(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    setStatus({ kind: "working", text: "Signing in..." });
    setPending(null);

    const { data, error } = await authClient.signIn.opaque({
      email: field(form, "email"),
      password: field(form, "password"),
    });

    if (error || !data) {
      setStatus({ kind: "error", text: errorText(error) });
      return;
    }

    form.reset();
    if (data.twoFactorRedirect) {
      setPending({ exportKey: data.exportKey, payloadToken: data.payloadToken });
      setStatus({ kind: "success", text: "Enter your two-factor code to finish signing in." });
      return;
    }
    await finishSignIn(data.payload, data.exportKey);
  }

  async function verify(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!pending) return;
    const form = event.currentTarget;
    setStatus({ kind: "working", text: "Verifying code..." });
    const result = await authClient.twoFactor.verifyTotp({
      code: field(form, "code"),
      trustDevice: new FormData(form).get("trustDevice") === "on",
    });
    if (result.error) {
      setStatus({ kind: "error", text: errorText(result.error) });
      return;
    }
    const loaded = await authClient.opaque.loadSignInPayload({
      payloadToken: pending.payloadToken,
    });
    const exportKey = pending.exportKey;
    setPending(null);
    if (loaded.error) {
      setStatus({ kind: "error", text: errorText(loaded.error) });
      return;
    }
    await finishSignIn(loaded.data.payload, exportKey);
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
      {pending ? (
        <form id="totp-form" onSubmit={verify}>
          <label>
            Code <input id="code" name="code" autoComplete="one-time-code" required />
          </label>
          <label>
            <input id="trust-device" name="trustDevice" type="checkbox" /> Trust this device
          </label>
          <button id="verify" type="submit">
            Verify code
          </button>
        </form>
      ) : null}
      <Status status={status} />
    </main>
  );
}
