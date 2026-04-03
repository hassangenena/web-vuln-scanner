const { contextBridge } = require("electron");

// Expose a safe API to the renderer
contextBridge.exposeInMainWorld("api", {
  fetch: (url, options) => fetch(url, options),
});