# Core UI Website

Vite + React documentation site for Core UI.

## Commands

```powershell
npm install
npm run dev
npm run build
npm run preview
```

## Content

- `src/i18n/` contains the English and Chinese page copy.
- `src/pages/` contains the documentation pages and code examples.
- `src/data/controls.ts` drives the controls catalog.
- `src/data/api-functions.ts` drives the C API reference.
- `src/data/uix-ai-guide.md` mirrors `../docs/uix-ai-guide.md` for the AI guide page.

Keep examples aligned with exported symbols in `../include/ui_core.h` and supported `.uix` syntax in `../docs/uix-guide.md`.
