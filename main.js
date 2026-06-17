const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const os = require('os');

let mainWindow;
let monitorProcess = null;

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
}

function startMonitor(targets) {
  stopMonitor();

  const filters = buildFilter(targets);
  const isWindows = process.platform === 'win32';

  if (isWindows) {
    // Windows: use PowerShell Get-NetTCPConnection + Get-NetUDPEndpoint
    monitorProcess = spawn('powershell', ['-NoProfile', '-Command', `
      $targets = @(${filters.map(f => `'${f}'`).join(',')});
      while ($true) {
        $conns = Get-NetTCPConnection -State Established | Where-Object {
          $remote = $_.RemoteAddress;
          $targets | ForEach-Object {
            if ($remote -like $_) { return $true }
          };
          return $false
        } | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,@{N='Protocol';E={'TCP'}},OwningProcess;
        
        $conns += Get-NetUDPEndpoint | Where-Object {
          $remote = $_.RemoteAddress;
          $targets | ForEach-Object {
            if ($remote -like $_) { return $true }
          };
          return $false
        } | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,@{N='Protocol';E={'UDP'}},OwningProcess;

        $result = @();
        foreach ($c in $conns) {
          try {
            $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue;
            $procName = if ($proc) { $proc.ProcessName } else { "unknown" };
          } catch { $procName = "unknown" };
          $result += [PSCustomObject]@{
            LocalAddress = $c.LocalAddress;
            LocalPort = $c.LocalPort;
            RemoteAddress = $c.RemoteAddress;
            RemotePort = $c.RemotePort;
            Protocol = $c.Protocol;
            Process = $procName;
            Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fff");
          };
        }
        Write-Host (ConvertTo-Json @{connections=$result} -Compress);
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
