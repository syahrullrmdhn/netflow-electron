const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const os = require('os');
const https = require('https');

let mainWindow;
let monitorProcess = null;
const CURRENT_VERSION = '1.0.4';
const REPO = 'syahrullrmdhn/netflow-electron';

// Simple update check via GitHub API
function checkForUpdates() {
  const opts = {
    hostname: 'api.github.com',
    path: `/repos/${REPO}/releases/latest`,
    headers: { 'User-Agent': 'NetFlow-Monitor', 'Accept': 'application/vnd.github.v3+json' },
  };

  https.get(opts, (res) => {
    let data = '';
    res.on('data', (chunk) => data += chunk);
    res.on('end', () => {
      try {
        const release = JSON.parse(data);
        const latestVersion = release.tag_name?.replace('v', '');
        if (latestVersion && latestVersion !== CURRENT_VERSION) {
          if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('update-status', {
              status: 'available',
              version: latestVersion,
              url: release.html_url,
            });
          }
        }
      } catch (e) {}
    });
  }).on('error', () => {});
}

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

  // Check for updates after window loads (every 30 min)
  checkForUpdates();
  setInterval(checkForUpdates, 30 * 60 * 1000);
}

function startMonitor(targets, intervalMs) {
  stopMonitor();

  const filters = buildFilter(targets);
  const isWindows = process.platform === 'win32';
  const pollMs = intervalMs || 1000;

  if (isWindows) {
    // Windows: use PowerShell Get-NetTCPConnection + bandwidth tracking
    monitorProcess = spawn('powershell', ['-NoProfile', '-Command', `
      $targets = @(${filters.map(f => `'${f}'`).join(',')});
      $prevAdapterBytes = @{};
      while ($true) {
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

        # Get per-adapter delta bytes (track each adapter separately)
        $deltaTotal = 0;
        try {
          $adapters = Get-NetAdapterStatistics -ErrorAction SilentlyContinue | Where-Object { $_.ReceivedBytes -gt 0 -or $_.SentBytes -gt 0 };
          foreach ($a in $adapters) {
            $current = $a.ReceivedBytes + $a.SentBytes;
            $prev = if ($prevAdapterBytes[$a.Name]) { $prevAdapterBytes[$a.Name] } else { $current };
            $delta = [Math]::Max(0, ($current - $prev));
            $deltaTotal += $delta;
            $prevAdapterBytes[$a.Name] = $current;
          }
        } catch { $deltaTotal = 0; }

        # Convert to MB (actual transferred during interval)
        $totalBwMB = [Math]::Round($deltaTotal / 1048576, 2);

        # Group by destination and count connections + track per-destination bytes
        $destStats = @{};
        foreach ($c in $conns) {
          $key = $c.RemoteAddress;
          if (-not $destStats[$key]) { 
            $destStats[$key] = @{ Count = 0; Conns = @(); };
          }
          $destStats[$key].Count += 1;
          $destStats[$key].Conns += $c;
        }

        # Proportional allocation per destination
        $totalConns = $conns.Count;
        $destMB = @{};
        if ($totalConns -gt 0) {
          foreach ($key in $destStats.Keys) {
            $ratio = $destStats[$key].Count / $totalConns;
            $destMB[$key] = [Math]::Round($ratio * $deltaTotal / 1048576, 2);
          }
        }

        # Build result with per-destination aggregation
        $result = @();
        $destinations = @();
        foreach ($key in $destStats.Keys) {
          $mb = if ($destMB[$key]) { $destMB[$key] } else { 0 };
          $destinations += [PSCustomObject]@{
            RemoteAddress = $key;
            Connections = $destStats[$key].Count;
            MB = $mb;
          };
          
          # Add individual connections
          foreach ($c in $destStats[$key].Conns) {
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
              MB = $mb;
            };
          }
        }
        Write-Host (ConvertTo-Json @{connections=$result;destinations=$destinations;totalBwMB=$totalBwMB} -Compress);
        Start-Sleep -Milliseconds ${pollMs};
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
ipcMain.handle('start-monitor', (_, targets, interval) => {
  startMonitor(targets, interval);
  return { status: 'started', targets };
});

ipcMain.handle('stop-monitor', () => {
  stopMonitor();
  return { status: 'stopped' };
});

ipcMain.handle('check-update', () => {
  checkForUpdates();
  return { status: 'checking' };
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
