import { createFileRoute } from "@tanstack/react-router";
import { authClient } from "../lib/auth-client";
import { fingerprint, generateDataKey, storeDataKey, wrapDataKey } from "../lib/demo-crypto";
import { Status, errorText, field, useStatus } from "../lib/status";

export const Route = createFileRoute("/sign-up")({ component: SignUp });

function SignUp() {
  const [status, setStatus] = useStatus();

  async function onSubmit(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    setStatus({ kind: "working", text: "Signing up..." });

    // The data key is generated here and wrapped under a KEK derived from the export key; the
    // plugin hands the export key to this callback locally, it never goes over the network.
    const dataKey = await generateDataKey();
    const { data, error } = await authClient.signUp.opaque({
      email: field(form, "email"),
      password: field(form, "password"),
      name: field(form, "name"),
      payload: async (exportKey: string) => wrapDataKey(dataKey, exportKey),
    });

    if (error || !data) {
      setStatus({ kind: "error", text: errorText(error) });
      return;
    }

    await storeDataKey(dataKey);
    setStatus({
      kind: "success",
      text: `Signed up. Key fingerprint: ${await fingerprint(dataKey)}`,
    });
  }

  return (
    <main>
      <h1>Sign up</h1>
      <form id="sign-up-form" onSubmit={onSubmit}>
        <label>
          Name <input id="name" name="name" type="text" autoComplete="name" required />
        </label>
        <label>
          Email <input id="email" name="email" type="email" autoComplete="email" required />
        </label>
        <label>
          Password{" "}
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="new-password"
            minLength={8}
            required
          />
        </label>
        <button type="submit" id="submit">
          Sign up
        </button>
      </form>
      <Status status={status} />
    </main>
  );
}
