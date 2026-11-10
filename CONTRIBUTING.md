# Code conventions

Keep changes focused and preserve behavior during readability refactors.

- Use rustfmt for Rust and Prettier for JavaScript, JSX, CSS, HTML, JSON, and YAML.
  Run `npm run format` before review and `npm run format:check` to verify formatting.
- Use descriptive names for scan results, rule matches, paths, and units. Keep IPC
  field names compatible with the frontend.
- Prefer straightforward control flow and small functions with a clear purpose.
  Introduce helpers or components when they remove meaningful duplication or
  isolate a responsibility, rather than merely moving code between files.
- Explain intent, constraints, and security decisions in comments. Avoid comments
  that restate the code or claim unfinished behavior is complete.
- Never put matched secrets or source lines in findings or logs. Keep scanner
  failures separate from findings and preserve coverage reporting.

Before submitting changes, run:

```sh
npm run format:check
npm run lint
npm run build
node --test tests/scanOutcome.test.js
cargo check --locked --manifest-path src-tauri/Cargo.toml
cargo clippy --locked --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path src-tauri/Cargo.toml
git diff --check
```

The older Vitest files in `src/__tests__` and `__tests__` describe the original
placeholder UI and are not part of the configured test suite. They need replacement
with current dashboard tests; formatting them does not validate their assertions.
