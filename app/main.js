const { app, BrowserWindow, shell, session } = require("electron");
const { spawn } = require("child_process");
const path = require("path");

let mainWindow;
let flaskProcess;

function startFlask() {
  const pythonCmd = process.platform === "win32" ? "python" : "python";
  const serverPath = path.join(__dirname, "..", "server.py");

  flaskProcess = spawn(pythonCmd, [serverPath], {
    cwd: path.join(__dirname, ".."),
    stdio: "pipe",
  });

  flaskProcess.stdout.on("data", (data) => {
    console.log("[Flask]", data.toString());
  });

  flaskProcess.stderr.on("data", (data) => {
    console.error("[Flask Error]", data.toString());
  });

  flaskProcess.on("close", (code) => {
    console.log("[Flask] exited with code", code);
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    titleBarStyle: "hiddenInset",
    backgroundColor: "#0a0e17",
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, "preload.js"),
    },
  });

  // Allow all requests to localhost
  session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
    callback({ requestHeaders: { ...details.requestHeaders } });
  });

  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        "Content-Security-Policy": [
          "default-src 'self' 'unsafe-inline' http://127.0.0.1:5000 https://fonts.googleapis.com https://fonts.gstatic.com; connect-src 'self' http://127.0.0.1:5000"
        ]
      }
    });
  });

  mainWindow.loadFile(path.join(__dirname, "index.html"));

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });
}

app.whenReady().then(() => {
  startFlask();
  // Wait a moment for Flask to start
  setTimeout(createWindow, 1500);
});

app.on("window-all-closed", () => {
  if (flaskProcess) flaskProcess.kill();
  if (process.platform !== "darwin") app.quit();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

app.on("before-quit", () => {
  if (flaskProcess) flaskProcess.kill();
});