const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const os = require('os');
const { autoUpdater } = require('electron-updater');

let mainWindow;
let monitorProcess = null;

// Configure auto-updater
autoUpdater.autoDownload = true;
autoUpdater.autoInstallOnAppQuit = true;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 960,
    height: 640,
    minWidth: 720,
    minHeight: 480,
    frame: false,
    titleBarStyle: 'hidden',
    backgroundColor: '#0a0a0f',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile('renderer/index.html');
  mainWindow.setTitle('NetFlow Monitor');

  // Check for updates after window loads
  autoUpdater.checkForUpdatesAndNotify();
}

function startMonitor(targets) {
  stopMonitor();

  const filters = buildFilter(targets);
  const isWindows = process.platform === 'win32';

  if (isWindows) {
    // Windows: use PowerShell Get-NetTCPConnection + bandwidth tracking
    monitorProcess = spawn('powershell', ['-NoProfile', '-Command', `
      $targets = @(${filters.map(f => `'${f}'`).join(',')});
      $prevBytes = @{};
      while ($true) {
        $t0 = Get-Date;
        
        $conns = Get-NetTCPConnection -State Established | Where-Object {
          $remote = $_.RemoteAddress;
          if ($targets -contains '*') { return $true };
          foreach ($t in $targets) { if ($remote -like $t) { return $true } };
          return $false;
        } | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,@{N='Protocol';E={'TCP'}},OwningProcess;
        
        $udp = Get-NetUDPEndpoint | Where-Object {
          $remote = $_.RemoteAddress;
          if ($targets -contains '*') { return $true };
          foreach ($t in $targets) { if ($remote -like $t) { return $true } };
          return $false;
        } | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,@{N='Protocol';E={'UDP'}},OwningProcess;
        $conns = @($conns) + @($udp);

        # Get interface bandwidth
        try {
          $adapters = Get-NetAdapterStatistics -ErrorAction SilentlyContinue;
          $totalBytes = 0;
          foreach ($a in $adapters) { $totalBytes += $a.ReceivedBytes + $a.SentBytes };
        } catch { $totalBytes = 0; }

        # Calculate per-destination bytes
        $destBytes = @{};
        $destCount = @{};
        foreach ($c in $conns) {
          $key = $c.RemoteAddress;
          if (-not $destCount[$key]) { $destCount[$key] = 0; }
          $destCount[$key] += 1;
        }

        # Proportional allocation based on connection count
        $totalConns = ($destCount.Values | Measure-Object -Sum).Sum;
        if ($totalConns -gt 0) {
          foreach ($key in $destCount.Keys) {
            $ratio = $destCount[$key] / $totalConns;
            $prev = if ($prevBytes[$key]) { $prevBytes[$key] } else { 0 };
            $current = $ratio * $totalBytes;
            $destBytes[$key] = [Math]::Max(0, ($current - $prev));
            $prevBytes[$key] = $current;
          }
        }

        $now = Get-Date;
        $elapsedSec = ($now - $t0).TotalSeconds;
        if ($elapsedSec -eq 0) { $elapsedSec = 1; }

        $result = @();
        foreach ($c in $conns) {
          try {
            $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue;
            $procName = if ($proc) { $proc.ProcessName } else { "unknown" };
          } catch { $procName = "unknown" };
          $bw = if ($destBytes[$c.RemoteAddress]) { [Math]::Round($destBytes[$c.RemoteAddress] / 1024, 1) } else { 0 };
          $result += [PSCustomObject]@{
            LocalAddress = $c.LocalAddress;
            LocalPort = $c.LocalPort;
            RemoteAddress = $c.RemoteAddress;
            RemotePort = $c.RemotePort;
            Protocol = $c.Protocol;
            Process = $procName;
            Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fff");
            BytesPerSec = $bw;
          };
        }
        Write-Host (ConvertTo-Json @{connections=$result;totalBwPerSec=[Math]::Round($totalBytes/$elapsedSec/1024,1)} -Compress);
        Start-Sleep -Milliseconds 1000;
      }
    `]);
  } else {
    // Linux/macOS: use netstat + lsof
    monitorProcess = spawn('bash', ['-c', `
      while true; do
        netstat -tn 2>/dev/null | awk 'NR>2' | while read proto recv send local remote state; do
          echo "$local|$remote|$proto|$state";
        done;
        sleep 1;
      done
    `]);
  }

  let buffer = '';
  monitorProcess.stdout.on('data', (data) => {
    buffer += data.toString();
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';

    for (const line of lines) {
      try {
        const parsed = isWindows ? JSON.parse(line) : parseNetstat(line);
        if (parsed && mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('traffic-data', parsed);
        }
      } catch (e) {
        // skip unparseable lines
      }
    }
  });

  monitorProcess.stderr.on('data', (data) => {
    console.error('Monitor stderr:', data.toString());
  });

  monitorProcess.on('close', (code) => {
    console.log('Monitor process exited with code', code);
    monitorProcess = null;
  });
}

function stopMonitor() {
  if (monitorProcess) {
    monitorProcess.kill();
    monitorProcess = null;
  }
}

function buildFilter(targets) {
  if (!targets || targets.length === 0) return ['*'];
  return targets.map(t => {
    if (t.includes('/')) {
      // CIDR prefix — match IPs in range
      const [ip, bits] = t.split('/');
      const prefix = ip.split('.').slice(0, Math.floor(parseInt(bits) / 8)).join('.');
      return prefix + '.*';
    }
    return t + '*';
  });
}

function parseNetstat(line) {
  // For non-Windows fallback
  const parts = line.split('|');
  if (parts.length < 4) return null;
  const [local, remote, proto] = parts;
  const [localAddr, localPort] = local.split(':');
  const [remoteAddr, remotePort] = remote.split(':');
  return {
    connections: [{
      LocalAddress: localAddr,
      LocalPort: parseInt(localPort) || 0,
      RemoteAddress: remoteAddr,
      RemotePort: parseInt(remotePort) || 0,
      Protocol: proto.toUpperCase(),
      Process: 'system',
      Timestamp: new Date().toISOString(),
    }],
  };
}

// IPC handlers
ipcMain.handle('start-monitor', (_, targets) => {
  startMonitor(targets);
  return { status: 'started', targets };
});

ipcMain.handle('stop-monitor', () => {
  stopMonitor();
  return { status: 'stopped' };
});

ipcMain.handle('check-update', () => {
  return autoUpdater.checkForUpdatesAndNotify();
});

ipcMain.handle('quit-and-install', () => {
  autoUpdater.quitAndInstall();
});

// Forward auto-updater events to renderer
autoUpdater.on('update-available', (info) => {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('update-status', { status: 'available', version: info.version });
  }
});

autoUpdater.on('update-not-available', () => {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('update-status', { status: 'none' });
  }
});

autoUpdater.on('download-progress', (progress) => {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('update-status', { status: 'downloading', percent: Math.floor(progress.percent) });
  }
});

autoUpdater.on('update-downloaded', () => {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('update-status', { status: 'downloaded' });
  }
});

autoUpdater.on('error', (err) => {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('update-status', { status: 'error', message: err.message });
  }
});

ipcMain.handle('window-minimize', () => mainWindow?.minimize());
ipcMain.handle('window-maximize', () => {
  if (mainWindow?.isMaximized()) {
    mainWindow.unmaximize();
  } else {
    mainWindow?.maximize();
  }
});
ipcMain.handle('window-close', () => mainWindow?.close());

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  stopMonitor();
  app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
