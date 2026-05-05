# Repository Notes

## Source Of Truth

This is the public GitHub-installable SDK repo for downstream internal tools:

- Remote: `https://github.com/andymarcus/internal-tools-sdk`
- Install form: `npm install github:andymarcus/internal-tools-sdk#vX.Y.Z`

The gateway repo also has an SDK copy at:

- `/Users/user/Documents/Codex/general-google-sso/packages/internal-tools-sdk/src/index.ts`
- `/Users/user/Documents/Codex/general-google-sso/packages/internal-tools-sdk/package.json`
- `/Users/user/Documents/Codex/general-google-sso/packages/internal-tools-sdk/README.md`

Whenever SDK behavior, types, README instructions, or package metadata are changed in the gateway repo, mirror the change here in the same work session.

Before pushing this public repo:

1. Run `npm run build`.
2. Run `npm run typecheck`.
3. Confirm `npm pack --dry-run` only includes SDK files.
4. Scan for secrets or gateway deployment config.
5. Commit, tag a new version when appropriate, and push.

Never add gateway app code, `.env` files, Google OAuth config, `INTERNAL_TOOLS`, downstream origins, shared secrets, or deployment-specific details to this public repo.
