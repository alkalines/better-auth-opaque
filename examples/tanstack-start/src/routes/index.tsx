import { createFileRoute, Link } from "@tanstack/react-router";
import { authClient } from "../lib/auth-client";
import { clearDataKey } from "../lib/demo-crypto";

export const Route = createFileRoute("/")({ component: Home });

function Home() {
  const { data: session, isPending } = authClient.useSession();

  async function signOut() {
    clearDataKey();
    await authClient.signOut();
  }

  return (
    <main>
      <h1>better-auth-opaque demo</h1>
      <p
        id="session-status"
        data-state={isPending ? "pending" : session ? "signed-in" : "signed-out"}
      >
        {isPending
          ? "Loading session..."
          : session
            ? `Signed in as ${session.user.email}`
            : "Signed out"}
      </p>
      {session ? (
        <button type="button" id="sign-out" onClick={signOut}>
          Sign out
        </button>
      ) : null}
      <p>
        <Link to="/two-factor">Manage two-factor authentication</Link>
      </p>
    </main>
  );
}
