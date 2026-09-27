import { defineConfig } from "eslint/config";
import next from "eslint-config-next";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default defineConfig([
    // .worktrees/ holds this repo's own linked-worktree checkouts (see
    // AGENTS.md) — each a full nested copy of the repo, including its own
    // generated .next/ build output. A config object with only `ignores`
    // applies globally (ESLint flat-config convention), unlike the
    // eslint-config-next preset's own ignores, which don't reach into
    // arbitrary subdirectories. Without this, `eslint .` from the main
    // repo root also lints every worktree's own .next/ artifacts, which
    // aren't even this repo's source (a real observed failure: a stray
    // worktree's build output threw a dozen unrelated lint errors here).
    { ignores: ['.worktrees/**'] },
    {
        extends: [...next],
    },
]);
