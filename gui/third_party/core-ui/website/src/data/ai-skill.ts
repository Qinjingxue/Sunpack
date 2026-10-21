// `?raw` is a Vite built-in: ships the file's contents as a string.
// Source of truth lives at `docs/uix-ai-guide.md` in the repo root —
// we keep a copy at `src/data/uix-ai-guide.md` and bump it whenever the
// upstream guide changes (see `scripts/sync-ai-guide.sh` if it exists).
import guide from "./uix-ai-guide.md?raw";

export const AI_SKILL_CONTENT = guide;
