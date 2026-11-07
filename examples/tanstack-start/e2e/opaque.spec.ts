import { expect, test, type Page } from "@playwright/test";

// Distinctive strings so that any appearance in a request is unambiguous.
const PASSWORDS = {
  flow1: "pw-flow1-Zk3vQ9-opaque",
  wrong: "pw-wrong-Hs7tL2-opaque",
  flow3Old: "pw-flow3old-Bn5xR8-opaque",
  flow3New: "pw-flow3new-Cm4yW6-opaque",
  flow4Old: "pw-flow4old-Dj2pF7-opaque",
  flow4New: "pw-flow4new-Ek9sG1-opaque",
};

const runId = Date.now().toString(36);
const emailFor = (label: string) => `${label}-${runId}@example.test`;

/** Every request body and URL the browser sent in any test, for the password-leak assertion. */
const sentRequests: { url: string; body: string }[] = [];

test.beforeEach(({ page }) => {
  page.on("request", (request) => {
    sentRequests.push({ url: request.url(), body: request.postData() ?? "" });
  });
});

test.afterAll(() => {
  expect(sentRequests.some((request) => request.body.length > 0)).toBe(true);
  for (const password of Object.values(PASSWORDS)) {
    for (const request of sentRequests) {
      expect(request.body, `request body to ${request.url}`).not.toContain(password);
      expect(request.url, "request URL").not.toContain(password);
    }
  }
});

async function openForm(page: Page, path: string) {
  await page.goto(path);
  // Wait for hydration so the submit handler (not a native form post) runs.
  await page.waitForLoadState("networkidle");
}

async function submitForm(page: Page, values: Record<string, string>) {
  for (const [name, value] of Object.entries(values)) {
    await page.locator(`#${name}`).fill(value);
  }
  await page.locator("#submit").click();
}

async function expectStatus(page: Page, state: "success" | "error", pattern: RegExp) {
  const status = page.locator("#status");
  await expect(status).toHaveAttribute("data-state", state, { timeout: 30_000 });
  await expect(status).toHaveText(pattern);
  return (await status.textContent()) ?? "";
}

function fingerprintOf(text: string): string {
  const match = /fingerprint: ([0-9a-f]{16})$/.exec(text);
  expect(match, `fingerprint in "${text}"`).not.toBeNull();
  return match![1]!;
}

async function signUp(page: Page, email: string, password: string): Promise<string> {
  await openForm(page, "/sign-up");
  await submitForm(page, { name: "E2E User", email, password });
  return fingerprintOf(await expectStatus(page, "success", /^Signed up\. Key fingerprint: /));
}

async function signIn(page: Page, email: string, password: string) {
  await openForm(page, "/sign-in");
  await submitForm(page, { email, password });
}

async function signInExpectingFingerprint(
  page: Page,
  email: string,
  password: string,
): Promise<string> {
  await signIn(page, email, password);
  return fingerprintOf(await expectStatus(page, "success", /^Signed in\. Key fingerprint: /));
}

async function signOut(page: Page) {
  await openForm(page, "/");
  await expect(page.locator("#session-status")).toHaveAttribute("data-state", "signed-in");
  await page.locator("#sign-out").click();
  await expect(page.locator("#session-status")).toHaveAttribute("data-state", "signed-out");
}

test("sign-up, sign-out, sign-in unwraps the same payload", async ({ page }) => {
  const email = emailFor("flow1");

  const signUpFingerprint = await signUp(page, email, PASSWORDS.flow1);
  await signOut(page);

  const signInFingerprint = await signInExpectingFingerprint(page, email, PASSWORDS.flow1);
  expect(signInFingerprint).toBe(signUpFingerprint);
});

test("wrong password and unknown email show the same error", async ({ page }) => {
  const email = emailFor("flow2");
  await signUp(page, email, PASSWORDS.flow1);
  await signOut(page);

  await signIn(page, email, PASSWORDS.wrong);
  const wrongPasswordText = await expectStatus(page, "error", /\S/);

  await signIn(page, emailFor("flow2-unknown"), PASSWORDS.wrong);
  const unknownEmailText = await expectStatus(page, "error", /\S/);

  expect(unknownEmailText).toBe(wrongPasswordText);
  await expect(page.locator("#status")).not.toContainText("fingerprint");
});

test("change password keeps the payload and invalidates the old password", async ({ page }) => {
  const email = emailFor("flow3");
  const originalFingerprint = await signUp(page, email, PASSWORDS.flow3Old);

  // Same tab: the data key stored by sign-up is what gets rewrapped.
  await openForm(page, "/change-password");
  await submitForm(page, {
    currentPassword: PASSWORDS.flow3Old,
    newPassword: PASSWORDS.flow3New,
  });
  const changedFingerprint = fingerprintOf(
    await expectStatus(page, "success", /^Password changed\. Key fingerprint: /),
  );
  expect(changedFingerprint).toBe(originalFingerprint);

  await signOut(page);

  const newPasswordFingerprint = await signInExpectingFingerprint(page, email, PASSWORDS.flow3New);
  expect(newPasswordFingerprint).toBe(originalFingerprint);
  await signOut(page);

  await signIn(page, email, PASSWORDS.flow3Old);
  await expectStatus(page, "error", /\S/);
  await expect(page.locator("#status")).not.toContainText("fingerprint");
});

test("password reset works once and the link cannot be reused", async ({ page }) => {
  const email = emailFor("flow4");
  await signUp(page, email, PASSWORDS.flow4Old);
  await signOut(page);

  await openForm(page, "/forgot");
  await submitForm(page, { email });
  await expectStatus(page, "success", /^Reset link created\.$/);
  const resetLink = page.locator("#reset-link");
  const resetUrl = await resetLink.getAttribute("href");
  expect(resetUrl).toMatch(/\/reset\?token=/);

  await resetLink.click();
  await page.waitForLoadState("networkidle");
  await expect(page.locator("#status")).toHaveText("Reset token is valid.");

  await submitForm(page, { newPassword: PASSWORDS.flow4New });
  await expectStatus(page, "success", /^Password reset\. New key fingerprint: [0-9a-f]{16}$/);

  await signInExpectingFingerprint(page, email, PASSWORDS.flow4New);
  await signOut(page);

  await signIn(page, email, PASSWORDS.flow4Old);
  await expectStatus(page, "error", /\S/);

  // The token was consumed by the reset; opening the link again must fail visibly.
  await openForm(page, new URL(resetUrl!).pathname + new URL(resetUrl!).search);
  await expectStatus(page, "error", /\S/);
  await submitForm(page, { newPassword: PASSWORDS.flow4Old });
  await expectStatus(page, "error", /\S/);
  await signIn(page, email, PASSWORDS.flow4Old);
  await expectStatus(page, "error", /\S/);
});
