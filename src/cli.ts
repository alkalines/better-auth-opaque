#!/usr/bin/env node
/**
 * `better-auth-opaque create-setup`: prints a new serenity server setup on stdout and a backup
 * warning on stderr, so `better-auth-opaque create-setup > secret-file` captures only the setup.
 * The setup comes from the exact serenity version this package pins.
 */
import { ready, server } from "@serenity-kit/opaque";

// Minimal view of Node's `process`: the package uses no Node imports or Node types, and the
// binary only runs under Node-compatible runtimes where this global exists.
type CliProcess = { argv: string[]; exitCode?: number | string | undefined };
const nodeGlobals = globalThis as { process?: CliProcess };
const cliProcess = nodeGlobals.process;

const USAGE = "Usage: better-auth-opaque create-setup";
const BACKUP_WARNING = [
  "This is your OPAQUE server setup (OPAQUE_SERVER_SETUP). Store it as a secret and back it up.",
  "Every registration record depends on it: if it is lost or replaced, every user must reset their password.",
  "Never commit it to version control.",
].join("\n");

const command = cliProcess?.argv[2];

if (command === "create-setup") {
  ready.then(() => {
    console.log(server.createSetup());
    console.error(BACKUP_WARNING);
  });
} else {
  console.error(USAGE);
  if (cliProcess) {
    cliProcess.exitCode = 1;
  }
}
