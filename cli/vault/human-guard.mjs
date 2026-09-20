import { spawnSync } from "node:child_process";

const AGENT_ENV_VARS = [
  ["ANTIGRAVITY_AGENT", "Antigravity Agent"],
  ["CURSOR_PROJECT_DIR", "Cursor IDE"],
  ["CURSOR_TRACE_ID", "Cursor Agent"],
  ["CLAUDE_CODE", "Claude Code"],
  ["HERMES_AGENT", "Hermes Agent"],
  ["OPENCODE_CLIENT", "OpenCode Agent"],
  ["AGENT_MODE", "Generic Agent Mode"],
  ["CI", "CI pipeline"],
  ["GITHUB_ACTIONS", "GitHub Actions"],
];

const AGENT_PROCESS_NAMES = [
  "opencode", "opencode.exe", "cursor", "cursor.exe", "code", "code.exe",
  "antigravity", "claude", "hermes", "agent", "copilot",
];

function detectAgentEnv(env = process.env) {
  for (const [k, desc] of AGENT_ENV_VARS) if (env[k]) return { isAgent: true, reason: desc + " ($" + k + ")" };
  return { isAgent: false };
}

const AGENT_PROCESS_NAMES_LOWER = AGENT_PROCESS_NAMES.map((s) => s.toLowerCase());

export function detectAgentAncestor(names = []) {
  for (const raw of names) {
    const n = String(raw).toLowerCase();
    if (AGENT_PROCESS_NAMES_LOWER.some((a) => n.includes(a))) return { isAgent: true, processName: String(raw) };
  }
  return { isAgent: false };
}

let cachedAncestry = null;

export function checkProcessAncestors({ platform = process.platform, pid = process.pid, run = spawnSync, maxDepth = 5 } = {}) {
  const isDefault = pid === process.pid && platform === process.platform && run === spawnSync && maxDepth === 5;
  if (isDefault && cachedAncestry !== null) {
    return cachedAncestry;
  }
  let result = { isAgent: false };
  try {
    if (platform === "win32") {
      // Use single quotes to avoid JS template issues; PowerShell script built via string concat
      const script = [
        '$current = Get-CimInstance Win32_Process -Filter "ProcessId = ' + Number(pid) + '"',
        'for ($i = 0; $i -lt ' + Number(maxDepth) + '; $i++) {',
        'if (-not $current -or $current.ParentProcessId -le 0) { break }',
        '$current = Get-CimInstance Win32_Process -Filter "ProcessId = $($current.ParentProcessId)"',
        'if ($current) { Write-Output ($current.ProcessId.ToString() + "`t" + $current.Name) }',
        '}',
      ].join('; ');
      const res = run('powershell', ['-NoProfile', '-NonInteractive', '-Command', script], { encoding: 'utf8', timeout: 2500, windowsHide: true });
      if (res.status === 0 && res.stdout) {
        const names = res.stdout.split(/\r?\n/).map((line) => line.split('\t').slice(1).join('\t')).filter(Boolean);
        result = detectAgentAncestor(names);
      }
    } else {
      const res = run('ps', ['-axo', 'pid=,ppid=,comm='], { encoding: 'utf8', timeout: 2500, windowsHide: true });
      if (res.status === 0 && res.stdout) {
        const processes = new Map();
        for (const line of res.stdout.split(/\r?\n/)) {
          const m = /^\s*(\d+)\s+(\d+)\s+(.+?)\s*$/.exec(line);
          if (m) processes.set(Number(m[1]), { parentPid: Number(m[2]), name: m[3] });
        }
        const names = [];
        let cur = Number(pid);
        for (let d = 0; d < maxDepth; d += 1) {
          const curInfo = processes.get(cur);
          if (!curInfo || curInfo.parentPid <= 0 || curInfo.parentPid === cur) break;
          const parent = processes.get(curInfo.parentPid);
          if (!parent) break;
          names.push(parent.name);
          cur = curInfo.parentPid;
        }
        result = detectAgentAncestor(names);
      }
    }
  } catch {
    // ignore
  }
  if (isDefault) {
    cachedAncestry = result;
  }
  return result;
}

export function assertInteractiveHumanSession({ input = process.stdin, env = process.env, ancestor, operation = "'vault reveal'" } = {}) {
  // Test bypass: allow vault tests to run without TTY/agent block, but still audit
  // This env is intended for CI/unit tests only; production should not set it.
  // Agent could set it, but then audit will show bypass-test actor.
  if (env.HETZER_BYPASS_HUMAN_GUARD === '1' || env.HETZER_TEST_BYPASS_GUARD === '1' || env.HETZER_ALLOW_NON_INTERACTIVE_REVEAL === '1') {
    return;
  }
  if (!input.isTTY) {
    throw new Error('Access Denied: ' + operation + ' requires a direct human interactive TTY.\nAutonomous agent / non-interactive programmatic secret revelation is blocked.');
  }
  const envCheck = detectAgentEnv(env);
  if (envCheck.isAgent) {
    throw new Error('Access Denied: ' + operation + ' blocked.\nReason: ' + envCheck.reason + ' detected.\nUse \'hetzer exec -- <command>\' for scoped injection.');
  }
  const ancestry = ancestor || checkProcessAncestors();
  if (ancestry.isAgent) {
    throw new Error('Access Denied: ' + operation + ' blocked.\nReason: Agent runtime \'' + ancestry.processName + '\' in ancestry.\nUse \'hetzer exec -- <command>\'.');
  }
}

export function isAgenticContext({ input = process.stdin, env = process.env } = {}) {
  if (!input.isTTY) return true;
  if (detectAgentEnv(env).isAgent) return true;
  if (checkProcessAncestors().isAgent) return true;
  return false;
}
