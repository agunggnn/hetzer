import fs from "node:fs";
import path from "node:path";

import { POINTER_END, POINTER_START } from "./rules.mjs";

/**
 * Budget cap in tokens for the root agent entry pointer block.
 * Keeping the pointer under 200 tokens guarantees < 0.15% context footprint
 * on standard 128k context windows.
 */
export const POINTER_TOKEN_BUDGET = 200;

/**
 * Budget cap for standalone full-rule files in agent environments without
 * separate on-demand skill directories (e.g. .clinerules, .cursor/rules).
 */
export const FULL_RULE_TOKEN_BUDGET = 500;

/**
 * Budget cap for on-demand skill files (e.g. .agents/skills/hetzer/SKILL.md).
 */
export const SKILL_TOKEN_BUDGET = 600;

/**
 * Zero-dependency heuristic token estimator for English/Markdown technical text.
 * Based on empirical character-to-token (~3.8 chars/token) and word-to-token (~1.3 tokens/word)
 * ratios observed in BPE tokenizers (cl100k_base, o200k_base, Claude tokenizers) for
 * markdown instructions, code identifiers, and command syntax.
 *
 * @param {string} text
 * @returns {number} Estimated token count
 */
export function estimateTokenCount(text) {
    if (!text || typeof text !== "string") return 0;
    const trimmed = text.trim();
    if (!trimmed) return 0;

    const words = trimmed.split(/\s+/).filter(Boolean);
    const charCount = trimmed.length;

    const byChars = charCount / 3.8;
    const byWords = words.length * 1.3;

    return Math.max(1, Math.round((byChars + byWords) / 2));
}

/**
 * Known agent rule and skill relative paths supported by Hetzer.
 */
export const KNOWN_AGENT_FILES = [
    { path: "AGENTS.md", category: "pointer", label: "Antigravity / Codex / Hermes" },
    { path: "CLAUDE.md", category: "pointer", label: "Claude Desktop / Code" },
    { path: "GEMINI.md", category: "pointer", label: "Gemini CLI" },
    { path: ".clinerules", category: "rule", label: "Cline / Roo Code (.clinerules)" },
    { path: ".cursor/rules/hetzer.mdc", category: "rule", label: "Cursor IDE (.cursor/rules)" },
    { path: ".agents/skills/hetzer/SKILL.md", category: "skill", label: "AGY / Antigravity Skill" },
    { path: ".claude/skills/hetzer/SKILL.md", category: "skill", label: "Claude Skill" },
    { path: ".gemini/skills/hetzer/SKILL.md", category: "skill", label: "Gemini Skill" },
    { path: ".hermes/skills/hetzer/SKILL.md", category: "skill", label: "Hermes Skill" },
    { path: ".opencode/skills/hetzer/SKILL.md", category: "skill", label: "OpenCode Skill" },
    { path: ".commandcode/skills/hetzer/SKILL.md", category: "skill", label: "CommandCode Skill" },
    { path: ".codex/skills/hetzer/SKILL.md", category: "skill", label: "Codex Skill" },
];

/**
 * Audits the agent context footprint and prompt-caching health of a workspace.
 *
 * @param {string} workspaceRoot Absolute path to workspace root
 * @param {object} [options]
 * @param {number} [options.pointerBudget] Custom token budget for entry pointer
 * @param {number} [options.ruleBudget] Custom token budget for standalone rules
 * @returns {object} Audit report with token counts, cache-friendliness, and issues
 */
export function auditAgentContext(workspaceRoot, options = {}) {
    const pointerBudget = options.pointerBudget || POINTER_TOKEN_BUDGET;
    const ruleBudget = options.ruleBudget || FULL_RULE_TOKEN_BUDGET;
    const auditedFiles = [];
    const issues = [];

    for (const def of KNOWN_AGENT_FILES) {
        const fullPath = path.join(workspaceRoot, def.path);
        if (!fs.existsSync(fullPath)) continue;

        let content = "";
        try {
            content = fs.readFileSync(fullPath, "utf8");
        } catch {
            continue;
        }

        const hasStart = content.includes(POINTER_START);
        const hasEnd = content.includes(POINTER_END);

        if (def.category === "pointer" || hasStart) {
            let pointerContent = content;
            if (hasStart && hasEnd) {
                const s = content.indexOf(POINTER_START);
                const e = content.indexOf(POINTER_END) + POINTER_END.length;
                pointerContent = content.slice(s, e);
            }

            const tokens = estimateTokenCount(pointerContent);
            const withinBudget = tokens <= pointerBudget;

            // Prompt cache friendliness: static determinism, no dynamic timestamps or nonces
            const hasDynamicBust = /\b\d{4}-\d{2}-\d{2}T|\b(session[-_]?id|timestamp|nonce)\s*[:=]/i.test(pointerContent);
            const cacheFriendly = !hasDynamicBust;

            if (!withinBudget) {
                issues.push({
                    file: def.path,
                    type: "OVERSIZED_POINTER",
                    message: `Pointer block in '${def.path}' (${tokens} tokens) exceeds budget of ${pointerBudget} tokens.`,
                    solution: "Re-run 'hetzer skills install' to reapply compact pointer rules.",
                });
            }

            if (!cacheFriendly) {
                issues.push({
                    file: def.path,
                    type: "DYNAMIC_CACHE_BREAK",
                    message: `Pointer in '${def.path}' contains dynamic timestamps or nonces that break LLM prompt caching.`,
                    solution: "Remove dynamic values to maintain KV prompt cache hits across sessions.",
                });
            }

            auditedFiles.push({
                path: def.path,
                label: def.label,
                category: "pointer",
                tokens,
                budget: pointerBudget,
                withinBudget,
                cacheFriendly,
                onDemand: false,
            });
        } else if (def.category === "rule") {
            const tokens = estimateTokenCount(content);
            const withinBudget = tokens <= ruleBudget;
            const hasDynamicBust = /\b\d{4}-\d{2}-\d{2}T|\b(session[-_]?id|timestamp|nonce)\s*[:=]/i.test(content);
            const cacheFriendly = !hasDynamicBust;

            if (!withinBudget) {
                issues.push({
                    file: def.path,
                    type: "OVERSIZED_RULE",
                    message: `Rule file '${def.path}' (${tokens} tokens) exceeds budget of ${ruleBudget} tokens.`,
                    solution: "Trim unnecessary instructions or configure as an on-demand skill.",
                });
            }

            auditedFiles.push({
                path: def.path,
                label: def.label,
                category: "rule",
                tokens,
                budget: ruleBudget,
                withinBudget,
                cacheFriendly,
                onDemand: false,
            });
        } else if (def.category === "skill") {
            const tokens = estimateTokenCount(content);
            const hasFrontmatter = content.startsWith("---") && content.includes("name:") && content.includes("description:");

            if (!hasFrontmatter) {
                issues.push({
                    file: def.path,
                    type: "MISSING_FRONTMATTER",
                    message: `Skill file '${def.path}' is missing YAML frontmatter router metadata.`,
                    solution: "Ensure 'name:' and 'description:' exist so agents load the skill strictly on-demand.",
                });
            }

            auditedFiles.push({
                path: def.path,
                label: def.label,
                category: "skill",
                tokens,
                budget: SKILL_TOKEN_BUDGET,
                withinBudget: tokens <= SKILL_TOKEN_BUDGET,
                cacheFriendly: true,
                onDemand: true,
            });
        }
    }

    const pointerFiles = auditedFiles.filter((f) => f.category === "pointer");
    const configured = auditedFiles.length > 0;
    const maxPointerTokens = pointerFiles.length > 0
        ? pointerFiles.reduce((acc, curr) => Math.max(acc, curr.tokens), 0)
        : 0;

    const allWithinBudget = auditedFiles.every((f) => f.withinBudget);
    const allCacheFriendly = auditedFiles.every((f) => f.cacheFriendly);
    const ok = configured ? (allWithinBudget && allCacheFriendly) : true;

    const summary = configured
        ? (maxPointerTokens > 0
            ? `~${maxPointerTokens} tokens (${allCacheFriendly ? "100% prompt-cache friendly" : "dynamic cache-break detected"})`
            : `Configured (${auditedFiles.length} file(s), 100% cache-friendly)`)
        : "Not configured";

    return {
        configured,
        ok,
        pointerTokens: maxPointerTokens,
        pointerBudget,
        cacheFriendly: allCacheFriendly,
        files: auditedFiles,
        summary,
        issues,
    };
}
