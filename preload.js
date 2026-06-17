const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  startMonitor: (targets, interval) => ipcRenderer.invoke('start-monitor', targets, interval),
  stopMonitor: () => ipcRenderer.invoke('stop-monitor'),
  checkUpdate: () => ipcRenderer.invoke('check-update'),
  minimize: () => ipcRenderer.invoke('window-minimize'),
  maximize: () => ipcRenderer.invoke('window-maximize'),
  close: () => ipcRenderer.invoke('window-close'),
  onTrafficData: (callback) => {
    ipcRenderer.on('traffic-data', (_, data) => callback(data));
    return () => ipcRenderer.removeAllListeners('traffic-data');
  },
  onUpdateStatus: (callback) => {
    ipcRenderer.on('update-status', (_, data) => callback(data));
    return () => ipcRenderer.removeAllListeners('update-status');
  },
});
