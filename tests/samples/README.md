# Test samples

APK binaries are intentionally NOT committed to this repo. Populate these
folders yourself with real (or intentionally-crafted test) APKs before
running the integration test:

- `original/`   — the legitimate, known-good app
- `clone/`      — a same-app-but-modified / re-signed / renamed variant
- `modified/`   — original with minor legitimate modifications (e.g. a patch)
- `unrelated/`  — a completely different app, used as a negative control

Suggested coverage (project rule, Phase 13):
1. Exact same APK
2. Same app, minor modification
3. Re-signed clone (same code, different signing cert)
4. Clone with changed package name
5. Clone with modified icon
6. Clone with changed strings
7. Obfuscated clone
8. Completely unrelated APK

Do not hardcode expected scores from these samples into the analyzers —
only into test assertions, and only loosely (e.g. "clone > unrelated"),
per project rule against inventing accuracy numbers.
