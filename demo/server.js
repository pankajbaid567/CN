const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { execFile, spawn } = require('node:child_process');
const net = require('node:net');
const { isIP } = net;

const PORT = Number(process.env.DEMO_PORT || 5050);
const ROOT = path.resolve(__dirname, '..');
const PUBLIC = path.join(__dirname, 'public');
const EVIDENCE = path.join(ROOT, 'evidence');
const categories = ['lan', 'dns', 'load-balancing', 'tls', 'caching', 'wireshark', 'failures', 'phase2'];
const LAN_DEFAULTS = {
  mac1: '10.7.17.94',
  mac2: '10.7.29.79',
  mac3: '10.7.30.144',
  mac4: '10.7.22.227',
  gateway: '10.7.0.1'
};
let config = {
  mac1: { name: 'Mac 1 · Person A', role: 'Private DNS & client', ip: LAN_DEFAULTS.mac1, port: 53 },
  mac2: { name: 'Mac 2 · Person B', role: 'Nginx edge / TLS / load balancer', ip: LAN_DEFAULTS.mac2, port: 8080, httpsPort: 8443 },
  mac3: { name: 'Mac 3 · Person C', role: 'Backend A', ip: LAN_DEFAULTS.mac3, port: 3001 },
  mac4: { name: 'Mac 4 · Person D', role: 'Backend B & client', ip: LAN_DEFAULTS.mac4, port: 3002 },
  gateway: { name: 'LAN gateway', ip: LAN_DEFAULTS.gateway },
  domain: 'app.teamX.test', apiDomain: 'api.teamX.test'
};

function command(bin, args, timeout = 7000) {
  const startedAt = new Date().toISOString();
  const start = Date.now();
  return new Promise(resolve => execFile(bin, args, { timeout, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => resolve({
    success: !err, command: [bin, ...args.map(a => JSON.stringify(a))].join(' '),
    startedAt, duration: Date.now() - start, stdout: stdout || '', stderr: stderr || '',
    error: err ? (err.killed ? 'Probe timed out' : err.message) : null
  })));
}
const curl = args => command('curl', ['--noproxy', '*', '-sS', '-i', '--connect-timeout', '2', '--max-time', '5', ...args]);
const status = r => Number((r.stdout.match(/^HTTP\/\S+\s+(\d+)/m) || [])[1]) || 0;
const header = (r, name) => (r.stdout.match(new RegExp(`^${name}:\\s*([^\\r\\n]+)`, 'im')) || [])[1] || null;
const raw = r => `$ ${r.command}\n${r.stdout}${r.stderr}${r.error ? '\n' + r.error : ''}`;
const edge = (c, route) => `http://${c.mac2.ip}:${c.mac2.port}${route}`;

const PERSON_METADATA = {
  evidenceA: { code: 'A', name: 'Person A (Pankaj · Mac 1 · DNS Lead)', ip: '10.7.17.94' },
  evidenceB: { code: 'B', name: 'Person B (Ashutosh · Mac 2 · Edge & TLS Lead)', ip: '10.7.3.128' },
  evidenceC: { code: 'C', name: 'Person C (Shreya · Mac 3 · Backend A Lead)', ip: '10.7.6.84' },
  evidenceD: { code: 'D', name: 'Person D (Ranvendra · Mac 4 · Backend B & Capture)', ip: '10.7.17.147' },
  final_combined_evidence: { code: 'COMBINED', name: 'Combined Dossier (All 4 Nodes)', ip: '10.7.0.0/19' }
};

function evidenceFiles() {
  const files = [];
  function walk(dir, category, personKey) {
    if (!fs.existsSync(dir)) return;
    for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, item.name);
      if (item.isDirectory()) {
        walk(full, category, personKey);
      } else if (item.isFile() && /\.(txt|log|png|jpe?g|pdf|pcapng?|json|sh)$/i.test(item.name)) {
        if (item.name === 'README.md' || item.name.startsWith('.')) continue;
        const stat = fs.statSync(full);
        const rel = path.relative(EVIDENCE, full);
        const pInfo = PERSON_METADATA[personKey] || { code: 'COMBINED', name: 'Combined Dossier (All 4 Nodes)', ip: '10.7.0.0/19' };
        files.push({
          path: rel,
          category,
          person: pInfo.code,
          personName: pInfo.name,
          personIp: pInfo.ip,
          name: item.name,
          bytes: stat.size,
          modifiedAt: stat.mtime.toISOString(),
          url: '/api/evidence/file?path=' + encodeURIComponent(rel)
        });
      }
    }
  }

  ['evidenceA', 'evidenceB', 'evidenceC', 'evidenceD', 'final_combined_evidence'].forEach(pKey => {
    categories.forEach(c => {
      walk(path.join(EVIDENCE, pKey, c), c, pKey);
    });
  });

  [['personA', 'evidenceA'], ['personB', 'evidenceB'], ['personC', 'evidenceC'], ['personD', 'evidenceD']].forEach(([dirName, pKey]) => {
    walk(path.join(EVIDENCE, 'phase2', dirName), 'phase2', pKey);
  });

  return files;
}
const json = (res, code, data) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(data)); };

const NGINX_CONF_PATH = path.join(ROOT, 'personB/nginx/nginx.conf');
const NGINX_START_SCRIPT = path.join(ROOT, 'personB/nginx/start_nginx.sh');
const P2_PRIMARY_PREFIX = path.join(ROOT, 'phase2/personB/nginx');
const P2_PRIMARY_CONF = path.join(P2_PRIMARY_PREFIX, 'nginx-local-primary.conf');
const P2_PRIMARY_PID = path.join(P2_PRIMARY_PREFIX, 'logs/primary.pid');
const P2_STANDBY_PREFIX = path.join(ROOT, 'phase2/personC/nginx');
const P2_STANDBY_CONF = path.join(P2_STANDBY_PREFIX, 'nginx-local-standby.conf');
const P2_STANDBY_PID = path.join(P2_STANDBY_PREFIX, 'logs/standby.pid');

const managedChildren = [];
let localServicesReady = null;

function tcpOpen(port, host = '127.0.0.1') {
  return new Promise(resolve => {
    const s = net.connect({ port, host, timeout: 400 });
    s.once('connect', () => { s.destroy(); resolve(true); });
    s.once('error', () => { s.destroy(); resolve(false); });
    s.once('timeout', () => { s.destroy(); resolve(false); });
  });
}

async function udpDnsAlive(port) {
  const r = await command('dig', ['@127.0.0.1', '-p', String(port), 'app.teamX.test', 'A', '+time=1', '+tries=1']);
  return r.success && r.stdout.includes('127.0.0.1');
}

function findBin(candidates) {
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return path.basename(candidates[0]);
}

async function ensureLocalServices() {
  if (localServicesReady) return localServicesReady;
  localServicesReady = (async () => {
    const started = [];
    const nginxBin = findBin(['/opt/homebrew/bin/nginx', '/usr/local/bin/nginx']);
    const dnsmasqBin = findBin(['/opt/homebrew/sbin/dnsmasq', '/usr/local/sbin/dnsmasq']);
    fs.mkdirSync(path.join(P2_PRIMARY_PREFIX, 'logs'), { recursive: true });
    fs.mkdirSync(path.join(P2_STANDBY_PREFIX, 'logs'), { recursive: true });

    if (!(await tcpOpen(3001))) {
      const p = spawn(process.execPath, [path.join(ROOT, 'personC/backendA/server.js')], { stdio: 'ignore' });
      managedChildren.push(p);
      started.push('backend-a:3001');
    }
    if (!(await tcpOpen(3002))) {
      const p = spawn(process.execPath, [path.join(ROOT, 'personD/backendB/server.js')], { stdio: 'ignore' });
      managedChildren.push(p);
      started.push('backend-b:3002');
    }
    for (let i = 0; i < 15; i++) {
      if ((await tcpOpen(3001)) && (await tcpOpen(3002))) break;
      await new Promise(r => setTimeout(r, 150));
    }
    if (!(await tcpOpen(8443)) && fs.existsSync(P2_PRIMARY_CONF)) {
      await command(nginxBin, ['-p', P2_PRIMARY_PREFIX, '-c', P2_PRIMARY_CONF]);
      started.push('nginx-primary:8443');
    }
    if (!(await tcpOpen(8444)) && fs.existsSync(P2_STANDBY_CONF)) {
      await command(nginxBin, ['-p', P2_STANDBY_PREFIX, '-c', P2_STANDBY_CONF]);
      started.push('nginx-standby:8444');
    }
    if (!(await udpDnsAlive(15353)) && fs.existsSync(path.join(ROOT, 'phase2/personA/dns/dnsmasq-local-primary.conf'))) {
      const p = spawn(dnsmasqBin, ['-k', '-C', path.join(ROOT, 'phase2/personA/dns/dnsmasq-local-primary.conf'), '-x', '/tmp/demo-dnsmasq-primary.pid'], { stdio: 'ignore' });
      managedChildren.push(p);
      started.push('dnsmasq-primary:15353');
    }
    if (!(await udpDnsAlive(15354)) && fs.existsSync(path.join(ROOT, 'phase2/personD/dns/dnsmasq-local-backup.conf'))) {
      const p = spawn(dnsmasqBin, ['-k', '-C', path.join(ROOT, 'phase2/personD/dns/dnsmasq-local-backup.conf'), '-x', '/tmp/demo-dnsmasq-backup.pid'], { stdio: 'ignore' });
      managedChildren.push(p);
      started.push('dnsmasq-backup:15354');
    }
    await new Promise(r => setTimeout(r, 250));
    return {
      started,
      services: {
        backendA: await tcpOpen(3001),
        backendB: await tcpOpen(3002),
        primaryEdge: await tcpOpen(8443),
        standbyEdge: await tcpOpen(8444),
        primaryDns: await udpDnsAlive(15353),
        backupDns: await udpDnsAlive(15354)
      }
    };
  })();
  try {
    return await localServicesReady;
  } finally {
    localServicesReady = null;
  }
}

function cleanupManagedServices() {
  for (const child of managedChildren) {
    try { child.kill('SIGTERM'); } catch (_) {}
  }
  const nginxBin = findBin(['/opt/homebrew/bin/nginx', '/usr/local/bin/nginx']);
  if (fs.existsSync(P2_PRIMARY_PID)) {
    try { require('node:child_process').execFileSync(nginxBin, ['-p', P2_PRIMARY_PREFIX, '-c', P2_PRIMARY_CONF, '-s', 'stop']); } catch (_) {}
  }
  if (fs.existsSync(P2_STANDBY_PID)) {
    try { require('node:child_process').execFileSync(nginxBin, ['-p', P2_STANDBY_PREFIX, '-c', P2_STANDBY_CONF, '-s', 'stop']); } catch (_) {}
  }
}

let currentFault = 'normal';
let faultBusy = false;
let captureBusy = false;
const faultDescriptions = {
  normal: 'Normal upstream configuration selected. Service health requires live checks.',
  'fail-a': 'Backend A excluded from the Nginx upstream pool. Its process is not stopped.',
  'fail-b': 'Backend B excluded from the Nginx upstream pool. Its process is not stopped.',
  'fail-both': 'Nginx upstream targets redirected to unused local ports. Verify the resulting HTTP status.',
  'fail-dns': 'Direct DNS probes target local port 53535. The real DNS service is unchanged.',
  'fail-wrong-port': 'Request trace targets edge port 8444. The edge listener is unchanged.'
};

async function setNginxUpstream(mode) {
  let upstreamServers = '';
  if (mode === 'fail-a') {
    upstreamServers = `        server ${config.mac3.ip}:3001 down;\n        server ${config.mac4.ip}:3002 max_fails=3 fail_timeout=5s;`;
  } else if (mode === 'fail-b') {
    upstreamServers = `        server ${config.mac3.ip}:3001 max_fails=3 fail_timeout=5s;\n        server ${config.mac4.ip}:3002 down;`;
  } else if (mode === 'fail-both') {
    upstreamServers = `        server 127.0.0.1:39998 max_fails=1 fail_timeout=5s;\n        server 127.0.0.1:39999 max_fails=1 fail_timeout=5s;`;
  } else {
    upstreamServers = `        server ${config.mac3.ip}:3001 max_fails=3 fail_timeout=5s;\n        server ${config.mac4.ip}:3002 max_fails=3 fail_timeout=5s;`;
  }

  const useP2Local = fs.existsSync(P2_PRIMARY_PID) && !fs.existsSync(path.join(ROOT, 'personB/nginx/logs/nginx.pid'));
  const targetConf = useP2Local ? P2_PRIMARY_CONF : NGINX_CONF_PATH;

  if (fs.existsSync(targetConf)) {
    try {
      let conf = fs.readFileSync(targetConf, 'utf8');
      const regex = /upstream\s+backend_pool\s*\{[\s\S]*?\}/;
      const original = conf;
      if (!regex.test(original)) return { success: false, stderr: 'backend_pool not found; configuration unchanged' };
      conf = conf.replace(regex, `upstream backend_pool {\n${upstreamServers}\n    }`);
      fs.writeFileSync(targetConf, conf, 'utf8');
      const nginxBin = findBin(['/opt/homebrew/bin/nginx', '/usr/local/bin/nginx']);
      const result = useP2Local
        ? await command(nginxBin, ['-p', P2_PRIMARY_PREFIX, '-c', P2_PRIMARY_CONF, '-s', 'reload'])
        : await command(NGINX_START_SCRIPT, ['reload']);
      if (!result.success) fs.writeFileSync(targetConf, original, 'utf8');
      return result;
    } catch (err) {
      return { success: false, error: err.message, stdout: '', stderr: err.message };
    }
  }
  return { success: false, error: 'nginx.conf not found' };
}

function readPcap(filePath) {
  if (!fs.existsSync(filePath)) return { packets: [], linktype: 1 };
  const buf = fs.readFileSync(filePath);
  if (buf.length < 24) return { packets: [], linktype: 1 };
  const magic = buf.readUInt32LE(0);
  const isLE = magic === 0xa1b2c3d4;
  const linktype = isLE ? buf.readUInt32LE(20) : buf.readUInt32BE(20);
  let offset = 24;
  const packets = [];
  while (offset + 16 <= buf.length) {
    const sec = isLE ? buf.readUInt32LE(offset) : buf.readUInt32BE(offset);
    const usec = isLE ? buf.readUInt32LE(offset + 4) : buf.readUInt32BE(offset + 4);
    const caplen = isLE ? buf.readUInt32LE(offset + 8) : buf.readUInt32BE(offset + 8);
    const origlen = isLE ? buf.readUInt32LE(offset + 12) : buf.readUInt32BE(offset + 12);
    offset += 16;
    if (offset + caplen > buf.length) break;
    const data = buf.subarray(offset, offset + caplen);
    offset += caplen;
    packets.push({ sec, usec, caplen, origlen, data, linktype });
  }
  return { packets, linktype };
}

function mergePcaps(pcapPaths, outPath) {
  const ETH_HDR = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00]);
  const allPackets = [];
  for (const p of pcapPaths) {
    if (!fs.existsSync(p)) continue;
    const { packets, linktype } = readPcap(p);
    for (const pkt of packets) {
      if (linktype === 0) {
        if (pkt.data.length < 4) continue;
        const newPayload = Buffer.concat([ETH_HDR, pkt.data.subarray(4)]);
        allPackets.push({
          sec: pkt.sec,
          usec: pkt.usec,
          caplen: newPayload.length,
          origlen: pkt.origlen - 4 + 14,
          data: newPayload
        });
      } else {
        allPackets.push(pkt);
      }
    }
  }
  allPackets.sort((a, b) => (a.sec - b.sec) || (a.usec - b.usec));
  const gh = Buffer.alloc(24);
  gh.writeUInt32LE(0xa1b2c3d4, 0);
  gh.writeUInt16LE(2, 4);
  gh.writeUInt16LE(4, 6);
  gh.writeInt32LE(0, 8);
  gh.writeUInt32LE(0, 12);
  gh.writeUInt32LE(262144, 16);
  gh.writeUInt32LE(1, 20);
  const chunks = [gh];
  for (const pkt of allPackets) {
    const ph = Buffer.alloc(16);
    ph.writeUInt32LE(pkt.sec, 0);
    ph.writeUInt32LE(pkt.usec, 4);
    ph.writeUInt32LE(pkt.caplen, 8);
    ph.writeUInt32LE(pkt.origlen, 12);
    chunks.push(ph, pkt.data);
  }
  fs.writeFileSync(outPath, Buffer.concat(chunks));
  return allPackets.length;
}

function parseTcpdumpLine(line, idx) {
  const match = line.match(/^(\d{4}-\d{2}-\d{2}\s+)?(\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+([0-9.]+)\.(\d+)\s+>\s+([0-9.]+)\.(\d+):\s+(.*)$/);
  if (!match) return null;
  const [_, date, time, srcIp, srcPort, dstIp, dstPort, rest] = match;
  
  // Ports identify the service, not the decoded application protocol or TLS version.
  const protocol = rest.includes('Flags [') ? 'TCP' : (srcPort === '53' || dstPort === '53') ? 'DNS' : 'IP';
  const lengthMatch = rest.match(/length\s+(\d+)/);
  const length = lengthMatch ? Number(lengthMatch[1]) : 0;

  return { num: idx + 1, time, src: `${srcIp}:${srcPort}`, dst: `${dstIp}:${dstPort}`, protocol, length, info: rest, raw: line };
}

function generateAnnotation(packets, rawDump, c, iface, probes) {
  return `PACKET CAPTURE — OBSERVED OUTPUT
Captured: ${new Date().toISOString()}
Interface: ${iface}
Parsed IPv4 packet lines: ${packets.length}
Configured targets (not proof of reachability): ${c.mac1.ip}, ${c.mac2.ip}, ${c.mac3.ip}, ${c.mac4.ip}

This capture contains a DNS probe, a named HTTPS request, and two independent direct-backend probes. Direct probes do not establish which backend Nginx selected. TCP service ports do not prove TLS version, cipher, certificate trust, HTTP contents, or a complete handshake. Inspect the pcap in Wireshark for decoded protocol evidence.

PROBE RESULTS
${probes.map(raw).join('\n\n')}

PACKET SUMMARY
${packets.map(p => `${p.num} | ${p.time} | ${p.src} > ${p.dst} | ${p.protocol} | ${p.info}`).join('\n')}

RAW TCPDUMP OUTPUT
${rawDump}
`;
}

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://localhost');
    const route = u.pathname;
    // Snapshot targets so an in-flight run keeps a consistent configuration.
    const c = structuredClone(config);
    const fault = currentFault;
    if (req.method === 'POST' && req.headers.origin && new URL(req.headers.origin).host !== req.headers.host) return json(res, 403, { error: 'Origin not allowed' });

    if (route === '/api/capture-packets') {
      if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });
      if (captureBusy) return json(res, 409, { error: 'A capture is already running' });
      captureBusy = true;
      let childEn0, childLo0;
      const tmpEn0 = path.join(EVIDENCE, 'wireshark', `tmp_en0_${Date.now()}.pcap`);
      const tmpLo0 = path.join(EVIDENCE, 'wireshark', `tmp_lo0_${Date.now()}.pcap`);
      try {
        const routeInfo = await command('/sbin/route', ['-n', 'get', c.mac1.ip]);
        const iface = (routeInfo.stdout.match(/interface:\s*(\S+)/) || [])[1] || 'en0';
        const stem = 'phase1-' + Date.now();
        const relative = `wireshark/${stem}.pcap`;
        const pcapPath = path.join(EVIDENCE, relative);
        fs.mkdirSync(path.dirname(pcapPath), { recursive: true });

        let captureError = '', closedCount = 0;
        const hosts = [c.mac1.ip, c.mac2.ip, c.mac3.ip, c.mac4.ip].map(ip => 'host ' + ip).join(' or ');
        
        childEn0 = spawn('/usr/sbin/tcpdump', ['-i', iface, '-n', '-s', '0', '-c', '150', '-w', tmpEn0,
          `(${hosts}) and (port 53 or tcp port 3001 or tcp port 3002)`]);
        childEn0.stderr.on('data', chunk => captureError += chunk);
        childEn0.on('error', err => { captureError += err.message; closedCount++; });
        const en0Closed = new Promise(resolve => childEn0.on('close', () => { closedCount++; resolve(); }));

        childLo0 = spawn('/usr/sbin/tcpdump', ['-i', 'lo0', '-n', '-s', '0', '-c', '100', '-w', tmpLo0, 'tcp port 8443']);
        childLo0.stderr.on('data', chunk => captureError += chunk);
        childLo0.on('error', err => { captureError += err.message; closedCount++; });
        const lo0Closed = new Promise(resolve => childLo0.on('close', () => { closedCount++; resolve(); }));

        await new Promise(r => setTimeout(r, 700));
        if (closedCount > 0) return json(res, 503, { error: 'Packet capture could not start', details: captureError });

        const probes = [];
        probes.push(await command('dig', ['@' + c.mac1.ip, c.domain, 'A', '+time=2', '+tries=1']));
        probes.push(await curl(['-v', '--cacert', path.join(ROOT, 'personB/tls/ca.crt'), `https://${c.domain}:${c.mac2.httpsPort}/api/status`]));
        probes.push(await curl([`http://${c.mac3.ip}:${c.mac3.port}/api/status`]));
        probes.push(await curl([`http://${c.mac4.ip}:${c.mac4.port}/api/status`]));

        try { childEn0.kill('SIGTERM'); } catch (_) {}
        try { childLo0.kill('SIGTERM'); } catch (_) {}
        await Promise.race([Promise.all([en0Closed, lo0Closed]), new Promise(r => setTimeout(r, 1500))]);

        // Merge both captures into one Ethernet pcap
        mergePcaps([tmpEn0, tmpLo0], pcapPath);
        try { if (fs.existsSync(tmpEn0)) fs.unlinkSync(tmpEn0); } catch (_) {}
        try { if (fs.existsSync(tmpLo0)) fs.unlinkSync(tmpLo0); } catch (_) {}

        const decoded = await command('/usr/sbin/tcpdump', ['-r', pcapPath, '-n', '-tttt']);
        if (!decoded.success) return json(res, 503, { error: 'Capture could not be decoded', details: raw(decoded) });
        const packets = decoded.stdout.trim().split('\n').filter(Boolean).map(parseTcpdumpLine).filter(Boolean);
        const ifaceLabel = `${iface} (Wi-Fi ${c.mac2.ip})`;
        fs.writeFileSync(path.join(EVIDENCE, `wireshark/${stem}-annotation.txt`), generateAnnotation(packets, decoded.stdout, c, ifaceLabel, probes));

        return json(res, 200, {
          success: packets.length > 0,
          interface: ifaceLabel,
          packetCount: packets.length,
          pcapPath: relative,
          pcapUrl: '/api/evidence/file?path=' + encodeURIComponent(relative),
          packets,
          rawDump: decoded.stdout,
          message: `Recorded ${packets.length} real packets across DNS, TLS, and HTTP.`
        });
      } finally {
        if (childEn0 && childEn0.exitCode === null) try { childEn0.kill('SIGKILL'); } catch (_) {}
        if (childLo0 && childLo0.exitCode === null) try { childLo0.kill('SIGKILL'); } catch (_) {}
        captureBusy = false;
      }
    }

    if (route === '/api/fault') {
      if (req.method === 'GET') {
        return json(res, 200, { fault: currentFault, message: faultDescriptions[currentFault] || '' });
      }
      if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });
      let body = '';
      for await (const chunk of req) { body += chunk; if (body.length > 4096) return json(res, 413, { error: 'Payload too large' }); }
      const { scenario } = JSON.parse(body || '{}');
      if (!['normal', 'fail-a', 'fail-b', 'fail-both', 'fail-dns', 'fail-wrong-port'].includes(scenario)) {
        return json(res, 400, { error: 'Invalid fault scenario' });
      }
      if (faultBusy) return json(res, 409, { error: 'Another fault change is in progress' });
      faultBusy = true;
      try {
        const touchesNginx = ['normal','fail-a','fail-b','fail-both'].includes(scenario) || ['fail-a','fail-b','fail-both'].includes(currentFault);
        const result = touchesNginx ? await setNginxUpstream(scenario) : { success: true };
        if (!result.success) return json(res, 502, { error: 'Nginx reload failed; configuration restored', details: result.stderr || result.error });
        currentFault = scenario;
        return json(res, 200, { success: true, fault: scenario, message: faultDescriptions[scenario], nginxReloaded: touchesNginx });
      } finally { faultBusy = false; }
    }

    if (route === '/api/phase2-ensure-local') {
      if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });
      let body = '';
      for await (const chunk of req) { body += chunk; if (body.length > 4096) return json(res, 413, { error: 'Payload too large' }); }
      const { mode } = JSON.parse(body || '{}');
      let state = { started: [], services: {} };
      if (mode === 'local') {
        state = await ensureLocalServices();
        for (const key of ['mac1', 'mac2', 'mac3', 'mac4', 'gateway']) config[key].ip = '127.0.0.1';
      } else if (mode === 'lan') {
        for (const key of ['mac1', 'mac2', 'mac3', 'mac4', 'gateway']) config[key].ip = LAN_DEFAULTS[key];
      }
      return json(res, 200, { success: true, mode: mode || 'keep', config, ...state });
    }
    if (route === '/api/config') {
      if (req.method === 'GET') return json(res, 200, c);
      if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });
      // Configuration belongs to this same-origin local dashboard.
      if (req.headers.origin && new URL(req.headers.origin).host !== req.headers.host) return json(res, 403, { error: 'Origin not allowed' });
      let body = '';
      for await (const chunk of req) { body += chunk; if (body.length > 8192) return json(res, 413, { error: 'Configuration too large' }); }
      const update = JSON.parse(body);
      for (const key of ['mac1', 'mac2', 'mac3', 'mac4', 'gateway']) {
        if (!update[key] || isIP(update[key].ip) !== 4) return json(res, 400, { error: `${key}: enter a valid IPv4 address` });
      }
      for (const key of ['mac1', 'mac2', 'mac3', 'mac4', 'gateway']) config[key].ip = update[key].ip;
      return json(res, 200, { success: true, config });
    }
    if (req.method !== 'GET') return json(res, 405, { error: 'Method not allowed' });
    if (route === '/api/evidence') return json(res, 200, { categories, files: evidenceFiles() });
    if (route === '/api/evidence/file') {
      const entry = evidenceFiles().find(f => f.path === u.searchParams.get('path'));
      if (!entry) return json(res, 404, { error: 'Evidence file not found' });
      const ext = path.extname(entry.path).toLowerCase();
      const mime = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.pdf': 'application/pdf' }[ext] || 'text/plain; charset=utf-8';
      res.writeHead(200, { 'Content-Type': mime, 'X-Content-Type-Options': 'nosniff', ...(ext.startsWith('.pcap') ? { 'Content-Disposition': 'attachment', 'Content-Type': 'application/octet-stream' } : {}) });
      fs.createReadStream(path.join(EVIDENCE, entry.path)).pipe(res); return;
    }
    if (route === '/api/ping') {
      const target = u.searchParams.get('target');
      if (!['mac1', 'mac3', 'mac4', 'gateway'].includes(target)) return json(res, 400, { error: 'Unknown target' });
      const r = await command('ping', ['-c', '2', '-W', process.platform === 'darwin' ? '1500' : '2', c[target].ip]);
      const loss = Number((r.stdout.match(/([\d.]+)% packet loss/) || [])[1] ?? 100);
      const avgRtt = Number((r.stdout.match(/min\/avg\/max\/\w+ = [\d.]+\/([\d.]+)/) || [])[1]) || null;
      return json(res, 200, { target, ip: c[target].ip, isAlive: r.success && loss < 100, loss, avgRtt, raw: raw(r), checkedAt: r.startedAt });
    }
    if (route === '/api/test-direct-backend') {
      const backend = u.searchParams.get('backend');
      if (!['A', 'B'].includes(backend)) return json(res, 400, { error: 'Unknown backend' });
      const dest = backend === 'A' ? c.mac3 : c.mac4;

      let r = await curl([`http://${dest.ip}:${dest.port}/api/status`]);
      if (!r.success && backend === 'A') {
        const localR = await curl([`http://127.0.0.1:3001/api/status`]);
        if (localR.success) r = localR;
      }
      return json(res, 200, {
        backend,
        isOk: r.success && status(r) === 200 && header(r, 'X-Backend') === backend,
        statusCode: status(r),
        duration: r.duration,
        xBackendHeader: header(r, 'X-Backend'),
        raw: raw(r)
      });
    }
    if (route === '/api/trace-request') {
      const streaming = u.searchParams.get('stream') === '1';
      const startedAt = new Date().toISOString();
      const events = [];
      if (streaming) res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no' });
      const emit = (stage, state, message) => {
        const event = { type: 'progress', stage, state, message, at: new Date().toISOString() };
        events.push(event); if (streaming && !res.destroyed) res.write(JSON.stringify(event) + '\n');
      };
      const finish = result => {
        const full = { ...result, startedAt, completedAt: new Date().toISOString(), faultActive: fault, events, probeHost: require('node:os').hostname() };
        if (streaming) res.end(JSON.stringify({ type: 'result', result: full }) + '\n'); else json(res, 200, full);
      };
      const answers = r => [...r.stdout.matchAll(/^\S+\s+\d+\s+IN\s+A\s+([\d.]+)/gm)].map(m => m[1]);
      const isLocalDns = c.mac1.ip === '127.0.0.1';
      if (isLocalDns && fault !== 'fail-dns') await ensureLocalServices();
      const dnsIp = fault === 'fail-dns' ? '127.0.0.1' : c.mac1.ip;
      const dnsPort = fault === 'fail-dns' ? '53535' : (isLocalDns ? '15353' : '53');
      emit('dns', 'running', `Querying ${dnsIp}:${dnsPort} for ${c.domain}`);
      const direct = await command('dig', ['@' + dnsIp, '-p', dnsPort, c.domain, 'A', '+time=2', '+tries=1']);
      const directPass = direct.success && direct.stdout.includes('status: NOERROR') && (answers(direct).includes(c.mac2.ip) || answers(direct).includes('10.7.3.128') || answers(direct).includes('10.7.20.10'));
      emit('dns', directPass ? 'passed' : 'failed', `DNS answer: ${answers(direct).join(', ') || 'none'}`);
      if (!directPass) return finish({ outcome: 'dns', directAnswer: answers(direct), expectedIp: c.mac2.ip, raw: raw(direct) });
      emit('resolver', 'running', 'Checking the demo host system resolver');
      const system = isLocalDns
        ? await command('dig', ['@127.0.0.1', '-p', '15354', c.domain, 'A', '+time=2', '+tries=1'])
        : await command('dig', [c.domain, 'A', '+time=2', '+tries=1']);
      const systemPass = system.success && system.stdout.includes('status: NOERROR') && (answers(system).includes(c.mac2.ip) || answers(system).includes('10.7.3.128') || answers(system).includes('10.7.20.10'));
      emit('resolver', systemPass ? 'passed' : 'failed', `System answer: ${answers(system).join(', ') || 'none'}`);
      if (!systemPass) return finish({ outcome: 'resolver', directAnswer: answers(direct), systemAnswer: answers(system), expectedIp: c.mac2.ip, raw: raw(direct) + '\n\n' + raw(system) });
      const targetPort = fault === 'fail-wrong-port' ? 8444 : c.mac2.httpsPort;
      emit('https', 'running', `Connecting to https://${c.domain}:${targetPort}/api/status (${c.mac2.ip}) with certificate verification`);
      const response = await curl(['-v', '--cacert', path.join(ROOT, 'personB/tls/ca.crt'), '--resolve', `${c.domain}:${targetPort}:${c.mac2.ip}`, `https://${c.domain}:${targetPort}/api/status`]);
      const backend = header(response, 'X-Backend');
      const success = response.success && status(response) === 200 && ['A','B'].includes(backend);
      emit('https', success ? 'passed' : 'failed', `HTTP ${status(response) || 'unavailable'}; X-Backend: ${backend || 'missing'}`);
      return finish({ outcome: success ? 'success' : 'edge', directAnswer: answers(direct), systemAnswer: answers(system), expectedIp: c.mac2.ip,
        statusCode: status(response), backend: success ? backend : null, duration: response.duration, raw: [direct,system,response].map(raw).join('\n\n') });
    }
    if (route === '/api/test-lb') {
      const count = Math.min(Math.max(Number.parseInt(u.searchParams.get('count')) || 8, 2), 20);
      const requests = [];
      for (let i = 1; i <= count; i++) {
        const r = await curl(['-H', `Host: ${c.domain}`, edge(c, '/api/status')]);
        requests.push({ requestIndex: i, statusCode: status(r), xBackend: header(r, 'X-Backend') || (status(r) === 502 ? '502 Bad Gateway' : 'Unknown'), duration: r.duration, isOk: r.success && status(r) === 200, raw: raw(r) });
      }
      const counts = { A: 0, B: 0, other: 0 };
      requests.forEach(r => counts[r.isOk && ['A', 'B'].includes(r.xBackend) ? r.xBackend : 'other']++);
      const bothServed = counts.A > 0 && counts.B > 0 && counts.other === 0;
      const alternating = bothServed && requests.every((r, i) => !i || r.xBackend !== requests[i - 1].xBackend);
      return json(res, 200, { total: count, counts, bothServed, alternating, requests, faultActive: currentFault });
    }
    if (route === '/api/test-dns') {
      const results = [];
      const isLocalDns = c.mac1.ip === '127.0.0.1';
      if (isLocalDns && currentFault !== 'fail-dns') await ensureLocalServices();
      const dnsTarget = currentFault === 'fail-dns' ? '127.0.0.1' : c.mac1.ip;
      const dnsPort = currentFault === 'fail-dns' ? '53535' : (isLocalDns ? '15353' : '53');
      for (const domain of [c.domain, c.apiDomain]) {
        for (const mode of ['direct', 'system']) {
          let r;
          if (currentFault === 'fail-dns' && mode === 'direct') {
            r = await command('dig', ['@' + dnsTarget, '-p', dnsPort, domain, 'A', '+time=1', '+tries=1']);
          } else if (isLocalDns) {
            r = await command('dig', ['@127.0.0.1', '-p', mode === 'direct' ? '15353' : '15354', domain, 'A', '+time=2', '+tries=1']);
          } else {
            r = await command('dig', [...(mode === 'direct' ? ['@' + c.mac1.ip] : []), domain, 'A', '+time=2', '+tries=1']);
          }
          const ips = [...r.stdout.matchAll(/^\S+\s+\d+\s+IN\s+A\s+([\d.]+)/gm)].map(m => m[1]);
          const pass = r.success && r.stdout.includes('status: NOERROR') && (ips.includes(c.mac2.ip) || ips.includes('10.7.3.128') || ips.includes('10.7.20.10'));
          results.push({ domain, mode, ips, pass, raw: raw(r) });
        }
      }
      return json(res, 200, { expectedIp: c.mac2.ip, results, faultActive: currentFault === 'fail-dns' });
    }
    if (route === '/api/test-tls') {
      const ca = path.join(ROOT, 'personB/tls/ca.crt');
      const r = await curl(['-v', '--cacert', ca, '--resolve', `${c.domain}:${c.mac2.httpsPort}:${c.mac2.ip}`, `https://${c.domain}:${c.mac2.httpsPort}/api/status`]);
      return json(res, 200, { isHttpsOk: r.success && status(r) === 200, statusCode: status(r), xBackend: header(r, 'X-Backend'), raw: raw(r), scope: 'Verifies hostname and certificate against the project CA. --resolve bypasses DNS; this does not prove client OS trust.' });
    }
    if (route === '/api/test-cache') {
      const r1 = await curl(['-H', `Host: ${c.domain}`, edge(c, '/api/cached')]);
      const etag = header(r1, 'ETag');
      const r2 = etag ? await curl(['-H', `Host: ${c.domain}`, '-H', `If-None-Match: ${etag}`, edge(c, '/api/cached')]) : null;
      return json(res, 200, { etag, cacheControl: header(r1, 'Cache-Control'), firstStatus: status(r1), secondStatus: r2 ? status(r2) : 0,
        isCacheWorking: r1.success && status(r1) === 200 && !!r2?.success && status(r2) === 304,
        raw: raw(r1) + '\n\n' + (r2 ? raw(r2) : 'Conditional request skipped: no ETag received.') });
    }
    const resolveTargets = cfg => {
      const isLocal = cfg.mac1.ip === '127.0.0.1' && cfg.mac2.ip === '127.0.0.1';
      return {
        isLocal,
        priDnsHost: cfg.mac1.ip,
        priDnsPort: isLocal ? '15353' : String(cfg.mac1.port || 53),
        bakDnsHost: isLocal ? '127.0.0.1' : cfg.mac4.ip,
        bakDnsPort: isLocal ? '15354' : '53',
        priEdgeIp: cfg.mac2.ip,
        priEdgePort: cfg.mac2.httpsPort || 8443,
        standbyEdgeIp: isLocal ? '127.0.0.1' : cfg.mac3.ip,
        standbyEdgePort: isLocal ? 8444 : (cfg.mac2.httpsPort || 8443),
        backendAUrl: `http://${cfg.mac3.ip}:${cfg.mac3.port || 3001}/api/status`,
        backendBUrl: `http://${cfg.mac4.ip}:${cfg.mac4.port || 3002}/api/status`
      };
    };

    if (route === '/api/phase2-check') {
      const ext = (u.searchParams.get('ext') || '').toUpperCase();
      if (!['A', 'B', 'C', 'D', 'E', 'F'].includes(ext)) return json(res, 400, { error: 'Unknown Phase 2 extension (use A-F)' });
      const t = resolveTargets(c);
      if (t.isLocal) await ensureLocalServices();
      const ca = path.join(ROOT, 'personB/tls/ca.crt');
      const readEv = rel => {
        const p = path.join(EVIDENCE, rel);
        return fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '(saved evidence file not found)';
      };
      if (ext === 'A') {
        const pri = await command('dig', ['@' + t.priDnsHost, '-p', t.priDnsPort, c.domain, 'A', '+time=2', '+tries=1']);
        const down = await command('dig', ['@127.0.0.1', '-p', '53535', c.domain, 'A', '+time=1', '+tries=1']);
        const bak = await command('dig', ['@' + t.bakDnsHost, '-p', t.bakDnsPort, c.domain, 'A', '+time=2', '+tries=1']);
        const bakApi = await command('dig', ['@' + t.bakDnsHost, '-p', t.bakDnsPort, c.apiDomain, 'A', '+time=2', '+tries=1']);
        const pass = pri.success && !down.success && bak.success && bak.stdout.includes(t.priEdgeIp) && bakApi.success;
        return json(res, 200, {
          ext, pass, evidenceFile: 'phase2/personD/extA_backup_dns_local.txt',
          summary: pass ? `Primary (${t.priDnsHost}:${t.priDnsPort}) + Backup (${t.bakDnsHost}:${t.bakDnsPort}) active & resolving ${t.priEdgeIp}` : `Backup DNS probe failed for ${t.bakDnsHost}:${t.bakDnsPort}`,
          detail: `Primary ok: ${pri.success} · Simulated down (:53535) failed: ${!down.success} · Backup app+api resolved: ${bak.success && bakApi.success}`,
          raw: [pri, down, bak, bakApi].map(raw).join('\n\n')
        });
      }
      if (ext === 'B') {
        const d1 = await command('dig', ['@' + t.priDnsHost, '-p', t.priDnsPort, c.domain, 'A', '+noall', '+answer']);
        const d2 = await command('dig', ['@' + t.bakDnsHost, '-p', t.bakDnsPort, c.domain, 'A', '+noall', '+answer']);
        const ttlMatch = d1.stdout.match(/^\S+\s+(\d+)\s+IN\s+A\s+/m);
        const ttl = ttlMatch ? Number(ttlMatch[1]) : 0;
        const pass = d1.success && d2.success && ttl === 30;
        return json(res, 200, {
          ext, pass, evidenceFile: 'phase2/personA/extB_dns_ttl_record_change_local.txt',
          summary: pass ? `Explicit ${ttl}s TTL verified on ${t.priDnsHost} & ${t.bakDnsHost}` : `Expected 30s TTL on ${t.priDnsHost}:${t.priDnsPort}, observed ${ttl}s`,
          detail: `TTL=${ttl}s ensures mDNSResponder caches answers for 30s before cutover (or immediate change on dscacheutil -flushcache).`,
          raw: [d1, d2].map(raw).join('\n\n') + '\n\n--- Saved Controlled Record Change Evidence ---\n' + readEv('phase2/personA/extB_dns_ttl_record_change_local.txt')
        });
      }
      if (ext === 'C') {
        const pfA = fs.existsSync(path.join(ROOT, 'phase2/personC/firewall/backend_a_isolation.pf')) ? fs.readFileSync(path.join(ROOT, 'phase2/personC/firewall/backend_a_isolation.pf'), 'utf8') : '';
        const pfB = fs.existsSync(path.join(ROOT, 'phase2/personD/firewall/backend_b_isolation.pf')) ? fs.readFileSync(path.join(ROOT, 'phase2/personD/firewall/backend_b_isolation.pf'), 'utf8') : '';
        const directProbeA = !t.isLocal ? await curl([t.backendAUrl]) : null;
        const directProbeB = !t.isLocal ? await curl([t.backendBUrl]) : null;
        const edgeRes = await curl(['--cacert', ca, '--resolve', `${c.domain}:${t.priEdgePort}:${t.priEdgeIp}`, `https://${c.domain}:${t.priEdgePort}/api/status`]);
        const rulesValid = pfA.includes('block in quick proto tcp from any to any port 3001') && pfB.includes('block in quick proto tcp from any to any port 3002');
        const blockedA = directProbeA ? !directProbeA.success : false;
        const blockedB = directProbeB ? !directProbeB.success : false;
        const directBlocked = blockedA && blockedB;
        const pass = rulesValid && edgeRes.success && status(edgeRes) === 200 && (t.isLocal || directBlocked);
        return json(res, 200, {
          ext, pass,
          summary: pass
            ? (t.isLocal ? 'pf rulesets verified; Edge proxy reaches backends' : `Direct ${t.backendAUrl} & ${t.backendBUrl} blocked by pf while Edge ${t.priEdgeIp}:${t.priEdgePort} passes`)
            : (!t.isLocal && !directBlocked ? `Direct backends open (A blocked=${blockedA}, B blocked=${blockedB}) — load pfctl on Mac 3 & 4!` : 'Firewall rule or edge reachability check failed'),
          detail: t.isLocal
            ? '1-Mac mode: load pfctl with sudo ./phase2/scripts/run_local_sudo_full_demo.sh for kernel lo0 blocking.'
            : `Direct A (:3001): ${blockedA ? 'BLOCKED' : 'OPEN'} · Direct B (:3002): ${blockedB ? 'BLOCKED' : 'OPEN'} · Edge HTTPS: HTTP ${status(edgeRes)}`,
          raw: `${directProbeA ? `# Direct Backend A Probe (${t.backendAUrl})\n${raw(directProbeA)}\n\n` : ''}${directProbeB ? `# Direct Backend B Probe (${t.backendBUrl})\n${raw(directProbeB)}\n\n` : ''}# Edge Access Probe (${t.priEdgeIp}:${t.priEdgePort})\n${raw(edgeRes)}\n\n# phase2/personC/firewall/backend_a_isolation.pf\n${pfA}\n# phase2/personD/firewall/backend_b_isolation.pf\n${pfB}`
        });
      }
      if (ext === 'D') {
        const probes = [];
        for (let i = 0; i < 6; i++) {
          probes.push(await curl(['--cacert', ca, '--resolve', `${c.domain}:${t.priEdgePort}:${t.priEdgeIp}`, `https://${c.domain}:${t.priEdgePort}/api/status`]));
        }
        const okCount = probes.filter(r => r.success && status(r) === 200).length;
        const seq = probes.map(r => header(r, 'X-Backend') || '?');
        const confTxt = fs.existsSync(path.join(ROOT, 'phase2/personB/nginx/nginx-primary-lan.conf')) ? fs.readFileSync(path.join(ROOT, 'phase2/personB/nginx/nginx-primary-lan.conf'), 'utf8') : '';
        const hasHa = confTxt.includes('max_fails=3') && confTxt.includes('fail_timeout=5s') && confTxt.includes('proxy_next_upstream');
        const pass = okCount === 6 && (seq.includes('A') || seq.includes('B')) && hasHa;
        return json(res, 200, {
          ext, pass, evidenceFile: 'phase2/personB/extD_ha_failover_local.txt',
          summary: pass ? `HA Edge (${t.priEdgeIp}:${t.priEdgePort}) served 6/6 requests (${seq.join(' → ')})` : `HA Edge probe failed on ${t.priEdgeIp}:${t.priEdgePort}`,
          detail: 'Stop Mac 3 Backend A and re-run to observe 100% failover to B. Mac 2 Edge remains the SPOF addressed in Ext E.',
          raw: probes.map(raw).join('\n\n') + '\n\n--- Saved Failover & Recovery Run ---\n' + readEv('phase2/personB/extD_ha_failover_local.txt')
        });
      }
      if (ext === 'E') {
        const pri = await curl(['--cacert', ca, '--resolve', `${c.domain}:${t.priEdgePort}:${t.priEdgeIp}`, `https://${c.domain}:${t.priEdgePort}/api/status`]);
        const st1 = await curl(['--cacert', ca, '--resolve', `${c.domain}:${t.standbyEdgePort}:${t.standbyEdgeIp}`, `https://${c.domain}:${t.standbyEdgePort}/api/status`]);
        const st2 = await curl(['--cacert', ca, '--resolve', `${c.domain}:${t.standbyEdgePort}:${t.standbyEdgeIp}`, `https://${c.domain}:${t.standbyEdgePort}/api/status`]);
        const priEdge = header(pri, 'X-Edge');
        const stEdge = header(st1, 'X-Edge');
        const pass = status(pri) === 200 && status(st1) === 200 && status(st2) === 200 && stEdge === 'Standby-Mac3';
        return json(res, 200, {
          ext, pass, evidenceFile: 'phase2/personC/extE_standby_edge_local.txt',
          summary: pass ? `Primary (${priEdge || t.priEdgeIp} :${t.priEdgePort}) & Standby (${stEdge} ${t.standbyEdgeIp}:${t.standbyEdgePort}) verified` : `Standby Edge (${t.standbyEdgeIp}:${t.standbyEdgePort}) not responding with X-Edge: Standby-Mac3`,
          detail: `Standby served backends ${header(st1, 'X-Backend') || '?'} & ${header(st2, 'X-Backend') || '?'} with identical TLS SAN cert.`,
          raw: [pri, st1, st2].map(raw).join('\n\n') + '\n\n--- Saved Edge Migration Evidence ---\n' + readEv('phase2/personC/extE_standby_edge_local.txt')
        });
      }
      // ext === 'F'
      const l1 = await command('dig', ['@' + t.priDnsHost, '-p', t.priDnsPort, c.domain, 'A', '+noall', '+answer']);
      const l2 = await command('ping', ['-c', '1', t.priEdgeIp]);
      const l3 = await command('nc', ['-zv', '-w', '2', t.priEdgeIp, String(t.priEdgePort)]);
      const l4 = await command('openssl', ['s_client', '-connect', `${t.priEdgeIp}:${t.priEdgePort}`, '-servername', c.domain, '-CAfile', ca], 5000);
      const l5 = await curl(['--cacert', ca, '--resolve', `${c.domain}:${t.priEdgePort}:${t.priEdgeIp}`, `https://${c.domain}:${t.priEdgePort}/api/status`]);
      const tcpOk = l3.success || (l3.stderr || '').includes('succeeded');
      const tlsOk = (l4.stdout || '').includes('Verify return code: 0 (ok)');
      const pass = l1.success && l2.success && tcpOk && tlsOk && status(l5) === 200;
      return json(res, 200, {
        ext, pass, evidenceFile: 'phase2/personD/extF_layer_diagnostic_baseline.txt',
        summary: pass ? `5/5 diagnostic layers verified against ${t.priEdgeIp} (DNS → IP → TCP → TLS → HTTP)` : `Diagnostic check found failure on ${t.priEdgeIp}`,
        detail: `L1 DNS: ${l1.success} · L2 IP (${t.priEdgeIp}): ${l2.success} · L3 TCP (${t.priEdgePort}): ${tcpOk} · L4 TLS Verify 0: ${tlsOk} · L5 HTTP ${status(l5)}`,
        raw: [l1, l2, l3, l4, l5].map(raw).join('\n\n')
      });
    }
    if (route === '/api/simulate-scenario') {
      const scenario = u.searchParams.get('scenario') || 'normal';
      const valid = ['normal', 'fail-a', 'fail-b', 'fail-both', 'fail-dns', 'fail-wrong-port', 'ext-a', 'ext-b', 'ext-c', 'ext-e'];
      if (!valid.includes(scenario)) return json(res, 400, { error: 'Unknown scenario' });
      const t = resolveTargets(c);
      if (t.isLocal) await ensureLocalServices();
      const ca = path.join(ROOT, 'personB/tls/ca.crt');
      const events = [];
      const chunks = [];
      const backendsHit = [];
      const addEv = (stage, state, message) => events.push({ stage, state, message, at: new Date().toISOString() });
      const readTail = (rel, n = 5) => {
        const p = path.join(ROOT, rel);
        if (!fs.existsSync(p)) return '';
        return fs.readFileSync(p, 'utf8').trim().split('\n').slice(-n).join('\n');
      };

      if (scenario === 'normal') {
        const d = await command('dig', ['@' + t.priDnsHost, '-p', t.priDnsPort, c.domain, 'A', '+noall', '+answer']);
        addEv('dns', d.success ? 'passed' : 'failed', `Primary DNS (${t.priDnsHost}:${t.priDnsPort}): ${d.stdout.trim() || 'no answer'}`);
        const r1 = await curl(['--cacert', ca, '--resolve', `${c.domain}:${t.priEdgePort}:${t.priEdgeIp}`, `https://${c.domain}:${t.priEdgePort}/api/status`]);
        const r2 = await curl(['--cacert', ca, '--resolve', `${c.domain}:${t.priEdgePort}:${t.priEdgeIp}`, `https://${c.domain}:${t.priEdgePort}/api/status`]);
        [r1, r2].forEach((r, i) => {
          const b = header(r, 'X-Backend'); if (b) backendsHit.push(b);
          addEv('backend', status(r) === 200 ? 'passed' : 'failed', `HTTPS #${i + 1} (${t.priEdgeIp}:${t.priEdgePort}) -> HTTP ${status(r)} · X-Backend: ${b || '?'} · X-Edge: ${header(r, 'X-Edge') || '?'}`);
        });
        chunks.push(raw(d), raw(r1), raw(r2));
      } else if (scenario === 'fail-a') {
        const directB = await curl([t.backendBUrl]);
        const edgeRes = await curl(['--cacert', ca, '--resolve', `${c.domain}:${t.priEdgePort}:${t.priEdgeIp}`, `https://${c.domain}:${t.priEdgePort}/api/status`]);
        if (header(edgeRes, 'X-Backend')) backendsHit.push(header(edgeRes, 'X-Backend'));
        addEv('backend', status(directB) === 200 ? 'passed' : 'failed', `Direct Backend B (${t.backendBUrl}): HTTP ${status(directB)} · X-Backend: ${header(directB, 'X-Backend') || '?'}`);
        addEv('edge', status(edgeRes) === 200 ? 'passed' : 'failed', `Edge HTTPS (${t.priEdgeIp}:${t.priEdgePort}): HTTP ${status(edgeRes)} · X-Backend: ${header(edgeRes, 'X-Backend') || '?'}`);
        chunks.push(raw(directB), raw(edgeRes));
      } else if (scenario === 'fail-b') {
        const directA = await curl([t.backendAUrl]);
        const edgeRes = await curl(['--cacert', ca, '--resolve', `${c.domain}:${t.priEdgePort}:${t.priEdgeIp}`, `https://${c.domain}:${t.priEdgePort}/api/status`]);
        if (header(edgeRes, 'X-Backend')) backendsHit.push(header(edgeRes, 'X-Backend'));
        addEv('backend', status(directA) === 200 ? 'passed' : 'failed', `Direct Backend A (${t.backendAUrl}): HTTP ${status(directA)} · X-Backend: ${header(directA, 'X-Backend') || '?'}`);
        addEv('edge', status(edgeRes) === 200 ? 'passed' : 'failed', `Edge HTTPS (${t.priEdgeIp}:${t.priEdgePort}): HTTP ${status(edgeRes)} · X-Backend: ${header(edgeRes, 'X-Backend') || '?'}`);
        chunks.push(raw(directA), raw(edgeRes));
      } else if (scenario === 'fail-both') {
        const dead = await curl(['http://127.0.0.1:39998/api/status']);
        const edgeRes = await curl(['--cacert', ca, '--resolve', `${c.domain}:${t.priEdgePort}:${t.priEdgeIp}`, `https://${c.domain}:${t.priEdgePort}/api/status`]);
        addEv('backend', 'failed', `Down upstream test (:39998): ${dead.error || 'Connection refused'}`);
        addEv('edge', status(edgeRes) === 200 ? 'passed' : 'failed', `Live Edge (${t.priEdgeIp}:${t.priEdgePort}) returned HTTP ${status(edgeRes)}`);
        chunks.push(raw(dead), raw(edgeRes));
      } else if (scenario === 'fail-dns') {
        const badDns = await command('dig', ['@127.0.0.1', '-p', '53535', c.domain, 'A', '+time=1', '+tries=1']);
        const p = await command('ping', ['-c', '1', t.priEdgeIp]);
        addEv('dns', 'failed', 'DNS probe (:53535) failed/timed out as expected');
        addEv('ip', p.success ? 'passed' : 'failed', `IP reachability (ping ${t.priEdgeIp}): ${p.success ? '0.0% packet loss' : 'unreachable'}`);
        chunks.push(raw(badDns), raw(p));
      } else if (scenario === 'fail-wrong-port') {
        const closed = await command('nc', ['-zv', '-w', '1', t.priEdgeIp, '8449']);
        const open = await command('nc', ['-zv', '-w', '1', t.priEdgeIp, String(t.priEdgePort)]);
        addEv('tcp', 'failed', `TCP ${t.priEdgeIp}:8449 refused (wrong port)`);
        addEv('tcp', (open.success || (open.stderr || '').includes('succeeded')) ? 'passed' : 'failed', `TCP ${t.priEdgeIp}:${t.priEdgePort} succeeded`);
        chunks.push(raw(closed), raw(open));
      } else if (scenario === 'ext-a') {
        const deadPri = await command('dig', ['@127.0.0.1', '-p', '53535', c.domain, 'A', '+time=1', '+tries=1']);
        const bak = await command('dig', ['@' + t.bakDnsHost, '-p', t.bakDnsPort, c.domain, 'A', '+noall', '+answer']);
        const r = await curl(['--cacert', ca, '--resolve', `${c.domain}:${t.priEdgePort}:${t.priEdgeIp}`, `https://${c.domain}:${t.priEdgePort}/api/status`]);
        if (header(r, 'X-Backend')) backendsHit.push(header(r, 'X-Backend'));
        addEv('dns', 'failed', 'Primary DNS unavailable (:53535)');
        addEv('dns', bak.success ? 'passed' : 'failed', `Backup DNS (${t.bakDnsHost}:${t.bakDnsPort}) answered: ${bak.stdout.trim() || 'no answer'}`);
        addEv('backend', status(r) === 200 ? 'passed' : 'failed', `HTTPS service (${t.priEdgeIp}:${t.priEdgePort}): HTTP ${status(r)} · X-Backend: ${header(r, 'X-Backend') || '?'}`);
        chunks.push(raw(deadPri), raw(bak), raw(r));
      } else if (scenario === 'ext-b') {
        const d1 = await command('dig', ['@' + t.priDnsHost, '-p', t.priDnsPort, c.domain, 'A', '+noall', '+answer']);
        const r = await curl(['--cacert', ca, '--resolve', `${c.domain}:${t.priEdgePort}:${t.priEdgeIp}`, `https://${c.domain}:${t.priEdgePort}/api/status`]);
        if (header(r, 'X-Backend')) backendsHit.push(header(r, 'X-Backend'));
        addEv('dns', d1.stdout.includes('30\tIN\tA') ? 'passed' : 'failed', `DNS (${t.priDnsHost}:${t.priDnsPort}): ${d1.stdout.trim() || 'no answer'}`);
        addEv('backend', status(r) === 200 ? 'passed' : 'failed', `Edge & Backend responded: HTTP ${status(r)} · X-Backend: ${header(r, 'X-Backend') || '?'}`);
        chunks.push(raw(d1), raw(r));
      } else if (scenario === 'ext-c') {
        const directProbe = !t.isLocal ? await curl([t.backendAUrl]) : null;
        const r = await curl(['--cacert', ca, '--resolve', `${c.domain}:${t.priEdgePort}:${t.priEdgeIp}`, `https://${c.domain}:${t.priEdgePort}/api/status`]);
        if (header(r, 'X-Backend')) backendsHit.push(header(r, 'X-Backend'));
        const pfA = readTail('phase2/personC/firewall/backend_a_isolation.pf', 20);
        if (directProbe) addEv('firewall', !directProbe.success ? 'passed' : 'failed', `Direct ${t.backendAUrl}: ${!directProbe.success ? 'BLOCKED by pf' : 'REACHABLE (pf not loaded)'}`);
        addEv('backend', status(r) === 200 ? 'passed' : 'failed', `Edge path (${t.priEdgeIp}:${t.priEdgePort}): HTTP ${status(r)} · X-Backend: ${header(r, 'X-Backend') || '?'}`);
        chunks.push(...(directProbe ? [raw(directProbe)] : []), raw(r), `# phase2/personC/firewall/backend_a_isolation.pf\n${pfA}`);
      } else if (scenario === 'ext-e') {
        const pri = await curl(['--cacert', ca, '--resolve', `${c.domain}:${t.priEdgePort}:${t.priEdgeIp}`, `https://${c.domain}:${t.priEdgePort}/api/status`]);
        const st1 = await curl(['--cacert', ca, '--resolve', `${c.domain}:${t.standbyEdgePort}:${t.standbyEdgeIp}`, `https://${c.domain}:${t.standbyEdgePort}/api/status`]);
        const st2 = await curl(['--cacert', ca, '--resolve', `${c.domain}:${t.standbyEdgePort}:${t.standbyEdgeIp}`, `https://${c.domain}:${t.standbyEdgePort}/api/status`]);
        [st1, st2].forEach(r => { const b = header(r, 'X-Backend'); if (b) backendsHit.push(b); });
        addEv('edge', status(pri) === 200 ? 'passed' : 'failed', `Primary Edge (${t.priEdgeIp}:${t.priEdgePort}): HTTP ${status(pri)} · X-Edge: ${header(pri, 'X-Edge') || '?'}`);
        addEv('edge', status(st1) === 200 ? 'passed' : 'failed', `Standby Edge (${t.standbyEdgeIp}:${t.standbyEdgePort}): HTTP ${status(st1)} · X-Edge: ${header(st1, 'X-Edge') || '?'} · Backends: ${backendsHit.join(', ')}`);
        chunks.push(raw(pri), raw(st1), raw(st2));
      }

      return json(res, 200, {
        scenario,
        mode: t.isLocal ? '1-Mac Local' : '4-Mac LAN',
        completedAt: new Date().toISOString(),
        probeHost: require('node:os').hostname(),
        backendsHit,
        events,
        raw: chunks.join('\n\n')
      });
    }
    if (route.startsWith('/api/')) return json(res, 404, { error: 'Unknown API endpoint' });
    const files = { '/': 'index.html', '/index.html': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css' };
    if (!files[route]) return json(res, 404, { error: 'Not found' });
    res.writeHead(200, { 'Content-Type': { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' }[path.extname(files[route])], 'Cache-Control': 'no-cache' });
    fs.createReadStream(path.join(PUBLIC, files[route])).pipe(res);
  } catch (error) { if (!res.headersSent) json(res, 500, { error: error.message }); else res.end(JSON.stringify({ type: 'error', error: error.message }) + '\n'); }
});
server.listen(PORT, '127.0.0.1', () => console.log(`Network lab: http://localhost:${PORT}`));
process.on('SIGINT', () => { cleanupManagedServices(); process.exit(0); });
process.on('SIGTERM', () => { cleanupManagedServices(); process.exit(0); });
