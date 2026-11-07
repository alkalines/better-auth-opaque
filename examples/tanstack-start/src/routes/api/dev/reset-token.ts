import { createFileRoute } from "@tanstack/react-router";
import { auth } from "../../../server/auth";

const LOOPBACK_HOSTNAMES: Record<string, true> = {
  localhost: true,
  "127.0.0.1": true,
  "[::1]": true,
};

/**
 * Dev-only stand-in for sending a reset email: hands the reset URL to the caller. Rejected unless
 * the request targets a loopback host and the app is not running in production. The Vite dev
 * server also binds to localhost only (vite.config.ts); never ship this route.
 */
function isLocalDevRequest(request: Request): boolean {
  if (process.env.NODE_ENV === "production") {
    return false;
  }

  // A proxy in front of the server means the client is not necessarily local.
  if (request.headers.has("x-forwarded-for") || request.headers.has("forwarded")) {
    return false;
  }

  const hostname = new URL(request.url).hostname;
  return LOOPBACK_HOSTNAMES[hostname] === true;
}

export const Route = createFileRoute("/api/dev/reset-token")({
  server: {
    handlers: {
      POST: async ({ request }: { request: Request }) => {
        if (!isLocalDevRequest(request)) {
          return Response.json({ error: "Forbidden" }, { status: 403 });
        }

        const body = (await request.json().catch(() => null)) as { email?: unknown } | null;
        if (typeof body?.email !== "string") {
          return Response.json({ error: "email is required" }, { status: 400 });
        }

        try {
          const { url } = await auth.api.createPasswordResetToken({
            body: { email: body.email },
          });
          return Response.json({ url });
        } catch (error) {
          const message = error instanceof Error ? error.message : "Could not create token";
          return Response.json({ error: message }, { status: 404 });
        }
      },
    },
  },
});
