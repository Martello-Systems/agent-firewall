/**
 * ESLint flat config (ESLint 9+).
 *
 * Lints the source, bin, and tests as modern ESM running on Node. Keeps the
 * rule set tight enough to catch real bugs (undeclared vars, unused vars,
 * unreachable code) without bikeshedding style.
 */
import js from "@eslint/js";
import globals from "globals";

export default [
  {
    ignores: ["node_modules/**", "**/*.sqlite", "coverage/**"],
  },
  js.configs.recommended,
  {
    files: ["**/*.js"],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "module",
      globals: {
        ...globals.node,
      },
    },
    rules: {
      "no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "no-console": "off",
      "no-empty": ["error", { allowEmptyCatch: true }],
      eqeqeq: ["error", "smart"],
      "prefer-const": "error",
    },
  },
];
