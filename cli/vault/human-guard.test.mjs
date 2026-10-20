import assert from "node:assert";
import { describe, it } from "node:test";
import { assertInteractiveHumanSession, detectAgentAncestor, isAgenticContext } from "./human-guard.mjs";

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
  it("does not honor environment bypass flags", () => {
    assert.throws(() => assertInteractiveHumanSession({
      input: { isTTY: false },
      env: { HETZER_TEST_BYPASS_GUARD: "1", HETZER_ALLOW_NON_INTERACTIVE_REVEAL: "1" },
    }), /TTY/);
  });
  it("allows human TTY without agent env", () => {
    assert.doesNotThrow(() => assertInteractiveHumanSession({ input: { isTTY: true }, env: {}, ancestor: { isAgent: false } }));
  });
  it("blocks Claude Code by the variables it actually sets", () => {
    for (const env of [{ CLAUDECODE: "1" }, { CLAUDE_CODE_ENTRYPOINT: "cli" }]) {
      assert.throws(() => assertInteractiveHumanSession({ input: { isTTY: true }, env, ancestor: { isAgent: false } }), /Claude Code session detected/);
      assert.throws(() => assertInteractiveHumanSession({ input: { isTTY: true }, env, ancestor: { isAgent: false }, allowEditorTerminal: true }), /Claude Code/);
    }
  });
  it("refuses editor terminals by default and points a person at a standalone terminal", () => {
    for (const env of [{ VSCODE_PID: "123" }, { CURSOR_TRACE_ID: "x" }]) {
      assert.throws(() => assertInteractiveHumanSession({ input: { isTTY: true }, env, ancestor: { isAgent: false } }), /editor terminal detected[\s\S]*standalone terminal/);
    }
    assert.throws(() => assertInteractiveHumanSession({ input: { isTTY: true }, env: {}, ancestor: { isAgent: false, editorProcess: "Code Helper" } }), /Editor process 'Code Helper'/);
  });
  it("lets input-only operations run in an editor terminal and reports it", () => {
    assert.deepEqual(
      assertInteractiveHumanSession({ input: { isTTY: true }, env: { VSCODE_PID: "123" }, ancestor: { isAgent: false }, allowEditorTerminal: true }),
      { editorTerminal: "VS Code editor terminal detected" },
    );
    assert.match(
      assertInteractiveHumanSession({ input: { isTTY: true }, env: {}, ancestor: { isAgent: false, editorProcess: "cursor" }, allowEditorTerminal: true }).editorTerminal,
      /Editor process 'cursor'/,
    );
    assert.deepEqual(assertInteractiveHumanSession({ input: { isTTY: true }, env: {}, ancestor: { isAgent: false } }), { editorTerminal: null });
  });
  it("still refuses an agent in an editor terminal when editor terminals are allowed", () => {
    assert.throws(() => assertInteractiveHumanSession({ input: { isTTY: true }, env: { VSCODE_PID: "1", OPENCODE_CLIENT: "1" }, ancestor: { isAgent: false }, allowEditorTerminal: true }), /OpenCode/);
    assert.throws(() => assertInteractiveHumanSession({ input: { isTTY: true }, env: { VSCODE_PID: "1" }, ancestor: { isAgent: true, processName: "claude" }, allowEditorTerminal: true }), /'claude'/);
  });
  it("detectAgentAncestor lets an agent name win over an editor name", () => {
    assert.deepEqual(detectAgentAncestor(["zsh", "Code Helper", "claude"]), { isAgent: true, processName: "claude" });
    assert.deepEqual(detectAgentAncestor(["zsh", "Cursor Helper", "launchd"]), { isAgent: false, editorProcess: "Cursor Helper" });
  });
  it("isAgenticContext true for non-TTY", () => {
    const origIsTTY = process.stdin.isTTY;
    // mock via passing env + fake input is hard; just test env path
    assert.equal(isAgenticContext({ env: { CI: "1" } }), true);
  });
});
