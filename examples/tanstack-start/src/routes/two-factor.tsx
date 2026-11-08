import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { authClient } from "../lib/auth-client";
import { Status, errorText, field, useStatus } from "../lib/status";

export const Route = createFileRoute("/two-factor")({ component: TwoFactor });

function TwoFactor() {
  const { data: session, isPending } = authClient.useSession();
  const [status, setStatus] = useStatus();
  const [setup, setSetup] = useState<{ secret: string; backupCodes: string[] } | null>(null);

  async function manage(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const disable = (event.nativeEvent as SubmitEvent).submitter?.id === "disable";
    setStatus({
      kind: "working",
      text: disable ? "Disabling two-factor..." : "Preparing two-factor...",
    });
    const proof = await authClient.opaque.createPasswordProof({
      password: field(form, "password"),
    });
    form.reset();
    if (proof.error) {
      setStatus({ kind: "error", text: errorText(proof.error) });
      return;
    }
    if (disable) {
      const result = await authClient.twoFactor.disable({ password: proof.data.proof });
      if (result.error) {
        setStatus({ kind: "error", text: errorText(result.error) });
        return;
      }
      setSetup(null);
      setStatus({ kind: "success", text: "Two-factor disabled" });
      return;
    }
    const result = await authClient.twoFactor.enable({ password: proof.data.proof });
    if (result.error) {
      setStatus({ kind: "error", text: errorText(result.error) });
      return;
    }
    if (result.data.method !== "totp") {
      setStatus({ kind: "error", text: "Expected authenticator setup." });
      return;
    }
    const secret = new URL(result.data.totpURI).searchParams.get("secret");
    if (!secret) {
      setStatus({ kind: "error", text: "Authenticator secret missing." });
      return;
    }
    setSetup({ secret, backupCodes: result.data.backupCodes });
    setStatus({
      kind: "success",
      text: "Enter an authenticator code to finish enabling two-factor.",
    });
  }

  async function verify(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    setStatus({ kind: "working", text: "Verifying code..." });
    const result = await authClient.twoFactor.verifyTotp({
      code: field(event.currentTarget, "code"),
    });
    if (result.error) {
      setStatus({ kind: "error", text: errorText(result.error) });
      return;
    }
    setSetup(null);
    setStatus({ kind: "success", text: "Two-factor enabled" });
  }

  if (isPending) return <main>Loading session...</main>;
  if (!session)
    return <main id="session-required">Sign in to manage two-factor authentication.</main>;

  return (
    <main>
      <h1>Two-factor authentication</h1>
      <form id="two-factor-form" onSubmit={manage}>
        <label>
          Current password{" "}
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
          />
        </label>
        <button id="enable" type="submit">
          Enable two-factor
        </button>
        <button id="disable" type="submit">
          Disable two-factor
        </button>
      </form>
      {setup ? (
        <section>
          <p>
            Authenticator secret: <code id="totp-secret">{setup.secret}</code>
          </p>
          <p>Save these backup codes somewhere safe:</p>
          <ul id="backup-codes">
            {setup.backupCodes.map((code) => (
              <li key={code}>{code}</li>
            ))}
          </ul>
          <form id="totp-setup-form" onSubmit={verify}>
            <label>
              Code <input id="code" name="code" autoComplete="one-time-code" required />
            </label>
            <button id="verify" type="submit">
              Verify code
            </button>
          </form>
        </section>
      ) : null}
      <Status status={status} />
    </main>
  );
}
