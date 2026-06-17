const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  startMonitor: (targets) => ipcRenderer.invoke('start-monitor', targets),
  stopMonitor: () => ipcRenderer.invoke('stop-monitor'),
  minimize: () => ipcRenderer.invoke('window-minimize'),
  maximize: () => ipcRenderer.invoke('window-maximize'),
  close: () => ipcRenderer.invoke('window-close'),
  onTrafficData: (callback) => {
    ipcRenderer.on('traffic-data', (_, data) => callback(data));
    return () => ipcRenderer.removeAllListeners('traffic-data');
  },
});
