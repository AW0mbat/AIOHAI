# AIOHAI Desktop — First Run Guide

**What this does:** Gets the Electron desktop app running on your dev machine so you can see the scaffold, verify the build toolchain works, and catch issues early.

**Time:** ~10 minutes  
**Difficulty:** Copy-paste commands

---

## Step 0 — Do You Have Node.js?

Open a terminal (PowerShell or Command Prompt) and run:

```
node --version
```

**If you see a version number** (like `v20.11.0`): Skip to Step 1.

**If you see an error** ("not recognized" / "not found"):

1. Go to https://nodejs.org
2. Download the **LTS** version (the green button on the left)
3. Run the installer — accept all defaults, click Next through everything
4. **Close and reopen your terminal** (important — the PATH needs to refresh)
5. Run `node --version` again — you should now see a version number
6. Also verify: `npm --version` — should show a version number

---

## Step 1 — Place the Desktop Folder

Unzip `aiohai-desktop-scaffold.zip`. You should get a `desktop/` folder.

Move it so your AIOHAI repo looks like this:

```
C:\AIOHAI\                    (or wherever your repo is)
├── aiohai/           ← NEW in v4.0.0 (layered package)
├── proxy/
├── security/
├── config/
├── policy/
├── desktop/          ← PUT IT HERE
│   ├── package.json
│   ├── src/
│   └── ...
├── tests/
└── README.md
```

It doesn't need to be in `C:\AIOHAI` on your dev machine — it can be anywhere. The folder structure just needs `desktop/` at the top level of the repo.

---

## Step 2 — Install Dependencies (One-Time Only)

Open a terminal and navigate to the desktop folder:

```
cd C:\path\to\your\repo\desktop
```

Then install all dependencies:

```
npm install
```

**This only needs to run once per machine.** After the initial install, you can use `start-aiohai.bat` for all future launches.

**What to expect:**
- Takes 1–3 minutes (downloads Electron + React + Vite + TypeScript)
- You'll see a progress bar and some output
- Warnings are normal (deprecation warnings, peer dependency warnings)
- **Errors are NOT normal** — if you see red `ERR!` lines, stop and share the output

When it finishes, you should see something like:
```
added 476 packages in 19s
```

**If you get a "running scripts is disabled" error in PowerShell:**
```
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```
Type `Y` to confirm, then retry `npm install`.

---

## Step 3 — Build the Main Process

The main process (Node.js side) needs to be compiled from TypeScript to JavaScript:

```
npm run build:main
```

**What to expect:**
- Should complete in 2–3 seconds
- No output means success
- If you see errors, they'll be TypeScript compilation errors — share them

This creates `desktop/dist/main/` with the compiled `.js` files.

---

## Step 4 — Start the Dev Server

Now start the Vite dev server (serves the React UI):

```
npm run dev:renderer
```

**What to expect:**
- You'll see output like:
  ```
  VITE v5.x.x  ready in 500ms

  ➜  Local:   http://localhost:5173/
  ```
- **Leave this terminal running** — it's serving the UI

---

## Step 5 — Launch the App

Open a **second terminal** (keep the first one running), navigate to the same folder:

```
cd C:\path\to\your\repo\desktop
```

Then launch Electron:

```
npm run start
```

**What to expect:**
- A desktop window should appear titled "AIOHAI Desktop"
- Dark background with a sidebar on the left (Chat, Approvals, Dashboard, Logs, Settings)
- Dashboard tab active with three health cards (Open WebUI, FIDO2, Ollama)
- All three cards will show **DOWN** (red) — this is correct, since these services aren't configured for your dev machine ports yet
- A status bar at the bottom with red/gray dots
- DevTools may open automatically (this is intentional in dev mode)

---

## Step 6 — Quick Verification Checklist

Click through each sidebar item and verify:

| Item | Expected |
|------|----------|
| **Chat** | "🚧" placeholder with "Build priority: #1" |
| **Approvals** | "🚧" placeholder with "Build priority: #2" |
| **Dashboard** | Three health cards, all showing "DOWN" |
| **Logs** | "🚧" placeholder with "Build priority: #3" |
| **Settings** | "🚧" placeholder with "Build priority: #4" |
| **Status bar** | Three red/gray dots, "No pending approvals" |

If you see all of this: **the scaffold is working.** The build toolchain, Electron, React, IPC bridge, and health monitoring are all functional.

---

## Step 7 — Test Against Your Open WebUI (Optional)

If you want to see a health card turn green, you can point the health monitor at your Docker Open WebUI instance.

In `src/main/main.ts`, find this block (~line 95):

```typescript
healthMonitor = new HealthMonitor({
  openWebUIUrl: 'http://localhost:3000',   // ← change this
  fido2Url: 'https://localhost:8443',
  ollamaUrl: 'http://localhost:11434',
  pollIntervalMs: 10000,
});
```

Change `localhost:3000` to `localhost:8090` (your Docker Open WebUI port).

Then:
1. Stop the Electron app (Ctrl+C in the second terminal, or close the window)
2. Rebuild: `npm run build:main`
3. Restart: `npm run start`

The Open WebUI health card should now show **HEALTHY** (green). The other two will still be red.

---

## Troubleshooting

### "npm is not recognized"
Node.js isn't installed or your terminal doesn't see it. Go back to Step 0.

### `npm install` fails with permission errors
Try running your terminal as Administrator, or use:
```
npm install --force
```

### `npm run build:main` shows TypeScript errors
Copy the full error output and share it — these are fixable.

### The Electron window is blank / white
The Vite dev server (Step 4) isn't running. Make sure the first terminal is still open and showing the Vite output.

### "Cannot find module" errors in the Electron console
Run `npm run build:main` again — the compiled JS files may be missing.

### Health cards all show "UNKNOWN" instead of "DOWN"
This is fine — it means the health check is timing out rather than getting a connection refused. Same practical meaning: service not reachable.

---

## Stopping Everything

**If you used `start-aiohai.bat`:** Just close the Electron window. The script cleans up Node processes automatically. Docker container stays running for faster next startup.

**If you started manually:**
1. Close the Electron window (or Ctrl+C in the second terminal)
2. Ctrl+C in the first terminal (stops the Vite dev server)

**To stop everything including Docker:** Double-click `stop-aiohai.bat`, or run `docker stop open-webui-dev` in PowerShell.

---

## Open WebUI Docker Setup

The desktop app needs an Open WebUI instance to connect to. If you don't have one:

```
docker run -d -p 3000:8080 --name open-webui-dev -e WEBUI_AUTH=True -e ENABLE_API_KEYS=True -e ENABLE_PERSISTENT_CONFIG=False ghcr.io/open-webui/open-webui:main
```

Then:
1. Go to `http://localhost:3000` and create an admin account
2. Go to **Admin Settings** and enable **API Keys** if not already on
3. Go to **Settings → Account → API Keys** and create a key
4. Use this key in the desktop app's connection setup

**Important:** The environment variable is `ENABLE_API_KEYS` (plural). This changed in Open WebUI v0.6.37. The singular `ENABLE_API_KEY` will not work.

---

## Daily Workflow

After the one-time setup is complete, your daily workflow is:

1. Make sure Docker Desktop is running
2. Double-click `start-aiohai.bat`
3. Use the app
4. Close the Electron window when done

---

## What Comes Next

The desktop app is being built in phases. Current status:

- [x] **Electron scaffold** — app opens, sidebar navigation, dark theme
- [x] **OpenWebUIClient** — API connection with Bearer token auth
- [x] **ConnectionSetup** — first-run wizard for URL and API key
- [ ] **ChatPanel** — SSE streaming chat with model selection
- [ ] **FIDO2 ApprovalModal** — Windows Hello / hardware key approval flow
- [ ] **LogViewer** — live proxy log stream with filtering
- [ ] **Dashboard enhancements** — proxy status, transparency reports
