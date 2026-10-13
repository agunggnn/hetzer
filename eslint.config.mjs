import js from "@eslint/js";
import globals from "globals";

export default [
    {
        ignores: ["artifacts/**", "data/**", ".hetzer/**", "backups/**", "benchmarks/rust-vault/**", "node_modules/**"]
    },
    js.configs.recommended,
    {
        files: ["**/*.mjs", "**/*.js"],
        languageOptions: {
            ecmaVersion: "latest",
            sourceType: "module",
            globals: { ...globals.node }
        }
    },
    {
        // Existing findings at adoption time. Kept as warnings so lint is usable now; promote to errors once cleaned up.
        rules: {
            "no-unused-vars": ["warn", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
            "no-empty": ["warn", { allowEmptyCatch: true }],
            "no-control-regex": "warn",
            "no-useless-escape": "warn",
            "no-useless-assignment": "warn",
            "preserve-caught-error": "warn",
            "no-regex-spaces": "warn",
            "no-dupe-else-if": "warn"
        }
    }
];
