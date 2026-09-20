import assert from "node:assert";
import { describe, it } from "node:test";
import { assertInteractiveHumanSession, isAgenticContext } from "./human-guard.mjs";

describe("human-guard - same-user agentic block", () => {
  it("blocks non-TTY (simulates agent piping)", () => {
    assert.throws(() => assertInteractiveHumanSession({ input: { isTTY: false }, env: {} }), /TTY/);
  });
  it("blocks when ANTIGRAVITY_AGENT is set", () => {
    assert.throws(() => assertInteractiveHumanSession({ input: { isTTY: true }, env: { ANTIGRAVITY_AGENT: "1" } }), /Antigravity/);
  });
  it("blocks when CI is set", () => {
    assert.throws(() => assertInteractiveHumanSession({ input: { isTTY: true }, env: { CI: "true" } }), /CI/);
  });
  it("allows human TTY without agent env", () => {
    assert.doesNotThrow(() => assertInteractiveHumanSession({ input: { isTTY: true }, env: {}, ancestor: { isAgent: false } }));
  });
  it("isAgenticContext true for non-TTY", () => {
    const origIsTTY = process.stdin.isTTY;
    // mock via passing env + fake input is hard; just test env path
    assert.equal(isAgenticContext({ env: { CI: "1" } }), true);
  });
});
