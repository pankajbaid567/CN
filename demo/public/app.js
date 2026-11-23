const $ = s => document.querySelector(s);
const escapeHtml = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const checks = [
  { id:'lan', number:'01', title:'LAN reachability', icon:'↔', description:'Can this machine reach the DNS host, both backends, and the gateway?', method:'ICMP ping from demo host', success:'Each target replies with packet loss below 100%.', caveat:'Probes originate on this demo host. This does not establish all-pair LAN reachability.', endpoint:null },
  { id:'backend-a', number:'02', title:'Backend A service (Mac 3 · Shreya)', icon:'◫', description:'Does Person C (Shreya) answer directly on port 3001?', method:'HTTP GET http://10.7.30.144:3001/api/status', success:'HTTP 200 OK with header X-Backend: A.', caveat:'Direct probe bypasses Nginx and tests microservice isolation.', endpoint:'/api/test-direct-backend?backend=A' },
  { id:'backend-b', number:'03', title:'Backend B service (Mac 4 · Ranvendra)', icon:'◫', description:'Does Person D (Ranvendra) answer directly on port 3002?', method:'HTTP GET http://10.7.22.227:3002/api/status', success:'HTTP 200 OK with header X-Backend: B.', caveat:'Direct probe bypasses Nginx and tests microservice isolation.', endpoint:'/api/test-direct-backend?backend=B' },
  { id:'lb', number:'04', title:'Load distribution (Round-Robin)', icon:'⇉', description:'Does Nginx edge on Mac 2 (Ashutosh) balance traffic across both backends?', method:'8 repeated GET /api/status requests via edge :8080', success:'Successful samples include both A and B. Exact order depends on concurrent traffic.', caveat:'When one upstream is excluded, verify every sampled request reached the remaining backend.', endpoint:'/api/test-lb?count=8' },
  { id:'dns', number:'05', title:'Private DNS resolution (Mac 1 · Pankaj)', icon:'◎', description:'Do app.teamX.test and api.teamX.test resolve via Person A (Pankaj)?', method:'Direct dig (@10.7.17.94) and system dig', success:'All four DNS probes return 10.7.29.79.', caveat:'Checks DNS answers from this host. Other client machines must be checked separately.', endpoint:'/api/test-dns' },
  { id:'tls', number:'06', title:'HTTPS & TLS termination (Mac 2 · Ashutosh)', icon:'◇', description:'Does edge serve valid HTTPS with private CA on :8443?', method:'curl --cacert ca.crt https://app.teamX.test:8443/api/status', success:'TLS handshake succeeds and returns HTTP 200.', caveat:'Bypasses DNS with --resolve to directly verify certificate chain.', endpoint:'/api/test-tls' },
  { id:'cache', number:'07', title:'Conditional HTTP caching', icon:'▥', description:'Does a repeat request with If-None-Match receive 304?', method:'GET /api/cached with ETag revalidation', success:'First request has ETag; second request returns 304 Not Modified.', caveat:'Proves HTTP conditional validation and bandwidth saving.', endpoint:'/api/test-cache' },
  { id:'trace', number:'08', title:'Named HTTPS request', icon:'⚡', description:'Does a complete request traverse DNS ➔ TLS Edge ➔ Upstream Backend?', method:'Full multi-protocol query from client to backend', success:'DNS matches the edge; verified HTTPS returns 200 with X-Backend.', caveat:'DNS and HTTPS command evidence. Packet capture is a separate requirement for Task G.', endpoint:'/api/trace-request' }
];

const failures = [
  ['Wrong DNS server / DNS Down', 'fail-dns', 'Name fails to resolve while edge IP may still be reachable.', 'Restore dnsmasq on Mac 1 (10.7.17.94) or reset Wi-Fi DNS.'],
  ['DNS points to wrong IP', 'fail-wrong-ip', 'Name resolves, but HTTPS reaches a host without the edge service.', 'Restore A record to 10.7.29.79 in dnsmasq and flush cache.'],
  ['Backend A stops (Failover to B)', 'fail-a', 'Nginx detects A down and routes 100% of traffic to Backend B.', 'Restart Backend A on Mac 3; traffic returns to round-robin.'],
  ['Backend B stops (Failover to A)', 'fail-b', 'Nginx detects B down and routes 100% of traffic to Backend A.', 'Restart Backend B on Mac 4; traffic returns to round-robin.'],
  ['Both backends stop (502 Bad Gateway)', 'fail-both', 'Edge proxy is reachable but returns HTTP 502 Bad Gateway.', 'Restart both Node processes on Mac 3 and Mac 4.'],
  ['Wrong destination port (8444)', 'fail-wrong-port', 'Address resolves and ping works; TCP connection is refused.', 'Connect to the configured edge port 8443.'],
  ['Ext A · Backup DNS Failover', 'ext-a', 'Primary DNS on Mac 1 stops, so clients automatically query Backup DNS on Mac 4.', 'Restart primary dnsmasq on Mac 1; both DNS servers stay synchronized.'],
  ['Ext B · 30s DNS TTL & Cache Flush', 'ext-b', 'OS resolver caches the old IP for 30s until TTL expires or dscacheutil -flushcache runs.', 'Lower TTL ahead of planned migrations and flush local cache for instant switch.'],
  ['Ext C · pf Backend Firewall Isolation', 'ext-c', 'Direct client calls to :3001/:3002 time out while Edge Nginx passes cleanly.', 'Load pf rules on Mac 3/4 and roll back with sudo pfctl -f /etc/pf.conf after demo.'],
  ['Ext E · Controlled Standby Edge Cutover', 'ext-e', 'DNS shifts app.teamX.test from Primary-Mac2 to Standby-Mac3 without replacing hardware.', 'Restore A record to Mac 2 IP once standby test concludes.']
];

const phase2Checks = [
  { ext:'A', title:'Backup DNS resolver', icon:'◎', owner:'EXTENSION A · PERSON D / A', desc:'Verifies Primary (:15353) + Backup (:15354) dnsmasq and shows Backup continues resolving when Primary stops.', rule:'phase2/personD/dns/', caveat:'Runs live dig probes against local Primary & Backup dnsmasq.' },
  { ext:'B', title:'DNS TTL (30s) & record change', icon:'◷', owner:'EXTENSION B · PERSON A', desc:'Confirms explicit 30-second TTL in dig answers and includes controlled IP cutover proof.', rule:'phase2/personA/dns/', caveat:'OS mDNSResponder port-53 flush is included in run_local_sudo_full_demo.sh.' },
  { ext:'C', title:'pf service isolation', icon:'🛡', owner:'EXTENSION C · PERSON C / D', desc:'Validates backend_a_isolation.pf & backend_b_isolation.pf rules and confirms Edge proxy reaches backends.', rule:'phase2/personC|D/firewall/', caveat:'Kernel pfctl enforcement requires sudo (run_local_sudo_full_demo.sh or Mac 3/4).' },
  { ext:'D', title:'HA failover & SPOF analysis', icon:'⇉', owner:'EXTENSION D · PERSON B', desc:'Probes Primary Edge (:8443) 6 times, checks passive health directives, and attaches live failover/recovery trace.', rule:'phase2/personB/nginx/', caveat:'Mac 2 Nginx remains the SPOF until paired with Ext E Standby Edge.' },
  { ext:'E', title:'Standby edge TLS & LB', icon:'⇄', owner:'EXTENSION E · PERSON C / A', desc:'Tests BOTH Primary (:8443, X-Edge: Primary-Mac2) and Standby (:8444, X-Edge: Standby-Mac3) with ca.crt.', rule:'phase2/personC/nginx/', caveat:'Both edges share the SAN certificate and balance across Backends A & B.' },
  { ext:'F', title:'5-layer troubleshooting baseline', icon:'⚡', owner:'EXTENSION F · ALL MEMBERS', desc:'Executes live bottom-up verification across Layer 7 DNS → L3 IP → L4 TCP → TLS → L7 HTTP.', rule:'PHASE2_HANDOVER.md', caveat:'Follow this exact 5-step order out loud during faculty fault injection.' }
];

let phase2State = {};
const pendingPhase2 = new Set();
let phase2AuditBusy = false;

let config, files = [], filter = 'all', selectedPerson = 'all', runState = {}, logState = {}, checkedAt = {}, flowBusy = false;
let currentScenario = 'normal', liveFault = 'normal';
const pendingChecks = new Set();
let auditBusy = false;

const api = async url => {
  const r = await fetch(url, { signal: AbortSignal.timeout(125000) });
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
};

async function apiPost(url, data) {
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
  const body = await r.json();
  if (!r.ok) throw new Error([body.error || `HTTP ${r.status}`, body.details].filter(Boolean).join(': '));
  return body;
}

function setNotice(text, level = 'info') {
  const n = $('#notice');
  if (n) {
    n.textContent = text;
    n.className = 'notice ' + level;
  }
}

const flowLabels = ['DNS query', 'DNS answer', 'HTTPS request', 'Nginx routes', 'Backend reply', 'Client response'];

function flowStatus(phase, message, evidence = '') {
  $('#flow-phase').textContent = phase;
  $('#flow-message').textContent = message;
  $('#flow-evidence').textContent = evidence;
}

function flowStep(index, activeNodes = []) {
  $('#flow-steps').innerHTML = flowLabels.map((label, i) =>
    `<span class="${i === index ? 'current' : i < index ? 'done' : ''}"><b>${String(i + 1).padStart(2, '0')}</b>${label}</span>`
  ).join('');
  document.querySelectorAll('.flow-diagram [data-node]').forEach(el =>
    el.classList.toggle('active', activeNodes.includes(el.dataset.node))
  );
}

function movePacket(pathId, reverse = false) {
  const path = document.getElementById(pathId), packet = $('#packet'), halo = $('#packet-halo');
  if (!path || !packet || !halo) return Promise.resolve();
  const short = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const duration = short ? 80 : 850;
  path.classList.add('travelling');
  for (const el of [packet,halo]) el.setAttribute('fill', reverse ? '#13a67c' : '#3779ff');
  packet.setAttribute('opacity', '1');
  halo.setAttribute('opacity', '.35');
  const length = path.getTotalLength();
  return new Promise(resolve => {
    const start = performance.now();
    function frame(now) {
      const t = Math.min((now - start) / duration, 1);
      const p = path.getPointAtLength((reverse ? 1 - t : t) * length);
      for (const el of [packet, halo]) {
        el.setAttribute('cx', p.x);
        el.setAttribute('cy', p.y);
      }
      if (t < 1) requestAnimationFrame(frame);
      else {
        path.classList.remove('travelling');
        packet.setAttribute('opacity', '0');
        halo.setAttribute('opacity', '0');
        resolve();
      }
    }
    requestAnimationFrame(frame);
  });
}

async function flowLeg(index, pathId, reverse, nodes, phase, message, evidence) {
  flowStep(index, nodes);
  flowStatus(phase, message, evidence);
  await movePacket(pathId, reverse);
}

function flowBusyState(busy) {
  flowBusy = busy;
  const playBtn = $('#play-flow'), sendBtn = $('#send-request');
  if (playBtn) playBtn.disabled = busy;
  if (sendBtn) sendBtn.disabled = busy;
  document.querySelectorAll('.fail-btn,#apply-fault,#configure').forEach(b => b.disabled = busy);
  if (!busy) $('#apply-fault').disabled = currentScenario === 'fail-wrong-ip';
}

const LIVE_SCENARIOS = ['normal', 'fail-a', 'fail-b', 'fail-both', 'fail-dns', 'fail-wrong-port'];

function setScenario(scenario) {
  if (flowBusy) return;
  currentScenario = scenario;
  document.querySelectorAll('.fail-btn').forEach(b => b.classList.toggle('active', b.id === `btn-scen-${scenario}`));
  const applyBtn = $('#apply-fault');
  if (applyBtn) {
    applyBtn.disabled = !LIVE_SCENARIOS.includes(scenario);
    applyBtn.textContent = LIVE_SCENARIOS.includes(scenario) ? 'Apply selected scenario to live lab' : 'Guided Phase 2 illustration (use Phase 2 checks below)';
  }
  $('#scenario-scope').textContent = 'Selected explanation: ' + scenario + '. Live lab state: ' + liveFault + '.';
  playFlow(false);
}

async function applyFault() {
  flowBusyState(true);
  try {
    const result = await apiPost('/api/fault', { scenario: currentScenario });
    liveFault = result.fault;
    runState = {}; logState = {}; renderChecks();
    $('#scenario-scope').textContent = result.message;
    setNotice(result.message + ' Run live checks to observe the effect.', 'info');
  } catch (error) { setNotice('Fault was not applied: ' + error.message, 'warn'); }
  finally { flowBusyState(false); }
}

async function streamTrace() {
  const response = await fetch('/api/trace-request?stream=1', { signal: AbortSignal.timeout(25000) });
  if (!response.ok) throw new Error('Trace endpoint returned HTTP ' + response.status);
  const reader = response.body.getReader(), decoder = new TextDecoder();
  let buffer = '', result;
  $('#flow-events').replaceChildren();
  for (;;) {
    const { done, value } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
    let end;
    while ((end = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
      if (!line.trim()) continue;
      const event = JSON.parse(line);
      if (event.type === 'error') throw new Error(event.error);
      if (event.type === 'result') result = event.result;
      if (event.type === 'progress') {
        const row = document.createElement('li'); row.className = event.state;
        row.textContent = `${new Date(event.at).toLocaleTimeString()} · ${event.message} · ${event.state}`;
        $('#flow-events').appendChild(row);
        flowStatus('Live probe · ' + event.stage, event.message, 'Events arrive as commands finish on the demo host. Moving dots illustrate the route after the result.');
        flowStep(event.stage === 'dns' ? 0 : event.stage === 'resolver' ? 1 : 2, [event.stage === 'dns' ? 'dns' : event.stage === 'resolver' ? 'client' : 'edge']);
      }
    }
    if (done) break;
  }
  if (!result) throw new Error('Trace ended without a final result');
  return result;
}

async function playFlow(live = false) {
  if (flowBusy) return;
  flowBusyState(true);
  $('#flow-raw-wrap').hidden = true;
  $('#flow-events').replaceChildren();
  document.querySelectorAll('.machine').forEach(m => m.classList.remove('node-failed', 'node-failover'));
  $('.client-chip strong').textContent = live ? 'Demo host client' : 'Client browser';
  $('.client-chip div span').textContent = live ? 'Actual probe source' : 'Simulation + background CLI';
  $('#flow-mode').textContent = live ? 'Live command progress' : 'Running terminal proof · ' + currentScenario;
  let result;
  const simPromise = !live
    ? api('/api/simulate-scenario?scenario=' + encodeURIComponent(currentScenario)).catch(err => ({ error: err.message }))
    : null;
  try {
    if (live) {
      flowStatus('Connecting to probe server', 'Starting live checks…', 'DNS and HTTPS are tested from the demo host.');
      result = await streamTrace();
      liveFault = result.faultActive;
      $('#flow-raw-wrap').hidden = false; $('#flow-raw').textContent = result.raw;
      runState.trace = interpret('trace', result); logState.trace = result.raw; checkedAt.trace = result.completedAt; renderChecks();
      $('#flow-mode').textContent = 'Observed result · illustrated route';
      if (result.outcome !== 'success') {
        const stage = result.outcome === 'dns' ? 0 : result.outcome === 'resolver' ? 1 : 2;
        flowStep(stage, [stage === 0 ? 'dns' : stage === 1 ? 'client' : 'edge']);
        flowStatus('Live probe stopped · ' + result.outcome,
          result.outcome === 'dns' ? 'The DNS answer did not match the configured edge.' : result.outcome === 'resolver' ? 'The demo host resolver did not return the edge address.' : 'The HTTPS request did not return a valid backend response.',
          `Source: ${result.probeHost}. Checked ${new Date(result.completedAt).toLocaleTimeString()}. See exact command output below.`);
        return;
      }
    }
    const illustration = 'Running real terminal probes in background against live local backends…';
    if (!live && currentScenario === 'ext-a') {
      await flowLeg(0,'route-dns',false,['client','dns'],'Ext A · Primary DNS down','Mac 1 dnsmasq stops responding on port 53.',illustration);
      await flowLeg(1,'route-dns',true,['b','client'],'Ext A · Backup DNS answers','Client falls back to Backup dnsmasq on Mac 4 and resolves app.teamX.test.',illustration);
      await flowLeg(2,'route-edge',false,['client','edge'],'Ext A · HTTPS continues','Service stays reachable via Primary Edge despite Mac 1 DNS outage.',illustration);
      flowStep(6,[]);
    } else if (!live && currentScenario === 'ext-b') {
      await flowLeg(0,'route-dns',false,['client','dns'],'Ext B · Initial lookup (TTL 30s)','OS resolver caches the returned Edge IP for 30 seconds.',illustration);
      await flowLeg(1,'route-dns',true,['dns','client'],'Ext B · Record updated','Even after DNS changes, client reuses cached IP until 30s expires or dscacheutil -flushcache runs.',illustration);
      flowStep(6,[]);
    } else if (!live && currentScenario === 'ext-c') {
      await flowLeg(2,'route-edge',false,['client','edge'],'Ext C · Client hits Edge only','pf rules on Mac 3/4 drop direct client access to :3001/:3002.',illustration);
      await flowLeg(3,'route-a',false,['edge','a'],'Ext C · Edge allowed by pf','Mac 2 Edge IP passes pf rule and reaches Backend A.',illustration);
      await flowLeg(4,'route-a',true,['a','edge'],'Ext C · Response via Edge','All traffic is forced through TLS termination & load balancing.',illustration);
      flowStep(6,[]);
    } else if (!live && currentScenario === 'ext-e') {
      await flowLeg(0,'route-dns',false,['client','dns'],'Ext E · DNS cutover (TTL 30s)','Person A updates app.teamX.test to Standby Edge Mac 3 IP.',illustration);
      await flowLeg(2,'route-a',false,['client','a'],'Ext E · Traffic moves to Standby Edge','New lookups route to Standby Nginx on Mac 3 (X-Edge: Standby-Mac3) with valid TLS.',illustration);
      await flowLeg(4,'route-b',true,['b','client'],'Ext E · Backends still balanced','Standby Edge distributes requests across Backends A and B.',illustration);
      flowStep(6,[]);
    } else {
      await flowLeg(0,'route-dns',false,['client','dns'],'01 · DNS query',live?'The demo host queried the private resolver.':'The client queries Person A’s DNS resolver.',live?`Observed from ${result.probeHost}.`:illustration);
      if (!live && currentScenario === 'fail-dns') {
        flowStatus('DNS failure + background check','A resolver timeout prevents the client from obtaining the edge address.','See live dig timeout & IP ping proof below.');
      } else {
        await flowLeg(1,'route-dns',true,['dns','client'],'02 · DNS answer',live?`Observed A record: ${result.expectedIp}`:'DNS returns the edge address to the client.',live?'The direct and system dig answers matched.':illustration);
        if (!live && currentScenario === 'fail-wrong-ip') {
          flowStatus('Wrong DNS record','DNS answers, but points the client to the wrong host.','Manual demonstration only: restore the A record to the actual edge IP.');
        } else {
          await flowLeg(2,'route-edge',false,['client','edge'],'03 · HTTPS request',live?'The demo host completed a verified HTTPS request.':'The client opens a connection to the Nginx edge.',live?'Certificate and hostname verified against the project CA.':illustration);
          if (!live && currentScenario === 'fail-wrong-port') {
            flowStatus('Wrong port + background check','A connection to an unused port is refused.','See live nc port probe proof below.');
          } else if (!live && currentScenario === 'fail-both') {
            await flowLeg(5,'route-edge',true,['edge','client'],'Expected error response','If no upstream is reachable, Nginx returns 502 Bad Gateway.',illustration);
          } else {
            const backends = live ? [result.backend] : currentScenario === 'fail-a' ? ['B'] : currentScenario === 'fail-b' ? ['A'] : ['A','B'];
            for (const [index,backend] of backends.entries()) {
              if (index) await flowLeg(2,'route-edge',false,['client','edge'],'Next independent request','The client sends a second request to Nginx.',illustration);
              const route = backend === 'A' ? 'route-a' : 'route-b', node = backend === 'A' ? 'a' : 'b';
              await flowLeg(3,route,false,['edge',node],'04 · Upstream route',`Nginx selects Backend ${backend} on Mac ${backend === 'A' ? '3' : '4'}.`,live?`Route inferred from observed X-Backend: ${backend}.`:illustration);
              await flowLeg(4,route,true,[node,'edge'],'05 · Backend reply',`Backend ${backend} returns a response through the edge.`,live?`Observed HTTP ${result.statusCode}; X-Backend: ${backend}.`:illustration);
              await flowLeg(5,'route-edge',true,['edge','client'],'06 · Response returns',live?'The response arrived at the demo host client.':'The response returns to the illustrated client.',live?`Measured HTTPS command duration: ${result.duration} ms.`:illustration);
            }
            flowStep(6,[]);
            flowStatus(live?'Live probe complete':'Walkthrough complete',live?`Verified HTTP 200 from Backend ${result.backend}.`:'Requests completed — loading live backend command output…',live?`Source: ${result.probeHost} · ${new Date(result.completedAt).toLocaleTimeString()}. Motion is a replay, not a packet capture.`:illustration);
          }
        }
      }
    }

    if (simPromise) {
      const sim = await simPromise;
      if (sim && !sim.error) {
        $('#flow-mode').textContent = `Simulation + live backend proof · ${currentScenario}`;
        (sim.events || []).forEach(ev => {
          const row = document.createElement('li');
          row.className = ev.state;
          row.textContent = `${new Date(ev.at).toLocaleTimeString()} · ${ev.message} · ${ev.state}`;
          $('#flow-events').appendChild(row);
        });
        const wrap = $('#flow-raw-wrap');
        wrap.hidden = false;
        wrap.open = true;
        $('#flow-raw').textContent = sim.raw || '(no command output)';
        if (sim.backendsHit?.length) {
          flowStatus(`Live proof complete (${currentScenario})`, `Real background commands hit Backend ${sim.backendsHit.join(' & ')}`, `Host: ${sim.probeHost} · ${new Date(sim.completedAt).toLocaleTimeString()}. Expand or inspect live terminal proof below.`);
        }
      }
    }
  } catch (error) {flowStep(-1,[]);flowStatus('Probe unavailable','Could not complete the trace.',error.message);}
  finally {flowBusyState(false);}
}

function renderConfig() {
  for (const [id, selector, port] of [['mac1', '#ip-dns', 53], ['mac2', '#ip-edge', 8443], ['mac3', '#ip-a', 3001], ['mac4', '#ip-b', 3002]]) {
    const el = $(selector);
    if (el) el.textContent = `${config[id].ip}:${port}`;
  }
  checks.find(c => c.id === 'backend-a').method = `HTTP GET ${config.mac3.ip}:3001/api/status`;
  checks.find(c => c.id === 'backend-b').method = `HTTP GET ${config.mac4.ip}:3002/api/status`;
  checks.find(c => c.id === 'dns').method = `Direct dig (@${config.mac1.ip}) and system dig`;
  checks.find(c => c.id === 'dns').success = `All four DNS probes return ${config.mac2.ip}.`;
  const isLocal = config.mac1.ip === '127.0.0.1' && config.mac2.ip === '127.0.0.1';
  const p2 = ext => phase2Checks.find(x => x.ext === ext);
  if (isLocal) {
    p2('A').desc = 'Verifies Primary (127.0.0.1:15353) + Backup (127.0.0.1:15354) dnsmasq and shows Backup continues resolving when Primary stops.';
    p2('B').desc = 'Confirms explicit 30-second TTL on 127.0.0.1:15353 & :15354 plus controlled IP cutover proof.';
    p2('C').desc = 'Validates backend_a_isolation.pf & backend_b_isolation.pf rules and confirms Edge proxy (127.0.0.1:8443) reaches backends.';
    p2('D').desc = 'Probes Primary Edge (127.0.0.1:8443) 6 times, checks passive health directives, and attaches live failover/recovery trace.';
    p2('E').desc = 'Tests BOTH Primary (127.0.0.1:8443, X-Edge: Primary-Mac2) and Standby (127.0.0.1:8444, X-Edge: Standby-Mac3) with ca.crt.';
    p2('F').desc = 'Executes live bottom-up verification across 127.0.0.1 (DNS :15354 → IP → TCP :8443 → TLS → HTTP).';
  } else {
    p2('A').desc = `Verifies Primary (${config.mac1.ip}:53) + Backup (${config.mac4.ip}:53) dnsmasq both resolve app.teamX.test to ${config.mac2.ip}.`;
    p2('B').desc = `Confirms explicit 30-second TTL on ${config.mac1.ip}:53 & ${config.mac4.ip}:53 plus controlled IP cutover proof.`;
    p2('C').desc = `Tests direct ${config.mac3.ip}:3001 & ${config.mac4.ip}:3002 are blocked by pf while Edge ${config.mac2.ip}:8443 succeeds.`;
    p2('D').desc = `Probes Primary Edge (${config.mac2.ip}:8443) 6 times across Mac 3 & Mac 4 and checks HA passive failover config.`;
    p2('E').desc = `Tests BOTH Primary Edge (${config.mac2.ip}:8443) and Standby Edge (${config.mac3.ip}:8443, X-Edge: Standby-Mac3) with ca.crt.`;
    p2('F').desc = `Executes live bottom-up verification on ${config.mac2.ip} (DNS :53 → IP → TCP :8443 → TLS → HTTP).`;
  }
  renderChecks();
  renderPhase2Checks();
  $('#config-fields').innerHTML = [['mac1', 'Mac 1 · DNS'], ['mac2', 'Mac 2 · Edge'], ['mac3', 'Mac 3 · Backend A'], ['mac4', 'Mac 4 · Backend B'], ['gateway', 'Gateway']].map(([id, label]) =>
    `<label class="form-field"><span>${label}</span><input name="${id}" required inputmode="decimal" value="${escapeHtml(config[id].ip)}" pattern="(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"></label>`
  ).join('');
  const inlineForm = $('#inline-ip-form');
  if (inlineForm) {
    for (const id of ['mac1', 'mac2', 'mac3', 'mac4', 'gateway']) {
      const inp = inlineForm.querySelector(`[name="${id}"]`);
      if (inp) inp.value = config[id].ip;
    }
  }
}

function interpret(id, data) {
  if (id === 'lan') {
    const passed = data.filter(x => x.isAlive).length;
    return {
      pass: passed === data.length,
      summary: `${passed}/${data.length} targets replied`,
      detail: data.map(x => `${x.target}: ${x.isAlive ? 'reachable' : 'no reply'} · ${x.loss}% loss`).join(' · '),
      raw: data.map(x => x.raw).join('\n\n')
    };
  }
  if (id === 'backend-a') {
    if (!data.isOk) {
      return {
        pass: false,
        summary: `Backend A probe failed (${data.statusCode ? 'HTTP ' + data.statusCode : data.error || 'unreachable'})`,
        detail: `${config.mac3.ip}:3001: ${data.error || 'No valid 200 response with expected backend header'}`,
        raw: data.raw
      };
    }
    return {
      pass: true,
      summary: `Backend A healthy (HTTP 200 · X-Backend: ${data.xBackendHeader})`,
      detail: `Direct response in ${data.duration}ms from Mac 3 (${config.mac3.ip}:3001)`,
      raw: data.raw
    };
  }
  if (id === 'backend-b') {
    if (!data.isOk) {
      return {
        pass: false,
        summary: `Backend B probe failed (${data.statusCode ? 'HTTP ' + data.statusCode : data.error || 'unreachable'})`,
        detail: `${config.mac4.ip}:3002: ${data.error || 'No valid 200 response with expected backend header'}`,
        raw: data.raw
      };
    }
    return {
      pass: true,
      summary: `Backend B healthy (HTTP 200 · X-Backend: ${data.xBackendHeader})`,
      detail: `Direct response in ${data.duration}ms from Mac 4 (${config.mac4.ip}:3002)`,
      raw: data.raw
    };
  }
  if (id === 'dns') {
    const passed = data.results.filter(x => x.pass).length;
    const pass = passed === 4;
    return {
      pass,
      summary: pass ? `4/4 DNS checks matched edge IP` : `${passed}/4 DNS checks matched (${data.faultActive ? 'Simulated DNS Outage' : 'Resolver issue'})`,
      detail: data.results.map(x => `${x.domain} (${x.mode}): ${x.ips.join(', ') || 'no answer'}`).join(' · '),
      raw: data.results.map(x => x.raw).join('\n\n')
    };
  }
  if (id === 'lb') {
    const isFaultA = data.faultActive === 'fail-a';
    const isFaultB = data.faultActive === 'fail-b';
    const isFaultBoth = data.faultActive === 'fail-both';

    let pass = data.bothServed;
    let summary = '';
    if (data.bothServed) {
      summary = `Both backends served traffic (${data.counts.A} A · ${data.counts.B} B)`;
    } else if (isFaultA && data.counts.B === data.total && data.counts.other === 0) {
      pass = true;
      summary = `Failover active: 100% served by Backend B (${data.counts.B} requests)`;
    } else if (isFaultB && data.counts.A === data.total && data.counts.other === 0) {
      pass = true;
      summary = `Failover active: 100% served by Backend A (${data.counts.A} requests)`;
    } else if (isFaultBoth && data.counts.other > 0) {
      pass = false;
      summary = `Unsuccessful responses: ${data.counts.other}; inspect their HTTP statuses`;
    } else {
      summary = `A ${data.counts.A} · B ${data.counts.B} · other ${data.counts.other}`;
    }

    return {
      pass,
      summary,
      detail: `Sequence: ${data.requests.map(x => x.xBackend).join(' → ')}. ${data.alternating ? 'Alternated round-robin.' : (pass && (isFaultA || isFaultB) ? 'All sampled requests used the configured remaining upstream.' : 'No complete distribution proof.')}`,
      raw: data.requests.map(x => x.raw).join('\n\n')
    };
  }
  if (id === 'tls') {
    return {
      pass: data.isHttpsOk,
      summary: data.isHttpsOk ? `Verified HTTPS · backend ${data.xBackend || 'unknown'}` : `HTTPS verification failed${data.statusCode ? ' (HTTP ' + data.statusCode + ')' : ''}`,
      detail: data.scope,
      raw: data.raw
    };
  }
  if (id === 'cache') {
    return {
      pass: data.isCacheWorking,
      summary: data.isCacheWorking ? '200 followed by 304 Not Modified' : `${data.firstStatus || 'No response'} followed by ${data.secondStatus || 'no response'}`,
      detail: `ETag: ${data.etag || 'missing'} · Cache-Control: ${data.cacheControl || 'missing'}`,
      raw: data.raw
    };
  }
  if (id === 'trace') {
    const pass = data.outcome === 'success';
    return {
      pass,
      summary: pass ? `Named HTTPS succeeded (Backend ${data.backend} · ${data.duration}ms)` : `Trace stopped at ${data.outcome} stage (${data.statusCode ? 'HTTP ' + data.statusCode : 'probe failure'})`,
      detail: pass
        ? `DNS resolved ${config?.domain || 'app.teamX.test'} → TLS handshake verified → Upstream Backend ${data.backend} replied HTTP 200`
        : `Trace interrupted at ${data.outcome} stage. Inspect output below.`,
      raw: data.raw
    };
  }
  return { pass: false, summary: 'Unknown check', detail: '', raw: '' };
}

function renderChecks() {
  $('#check-grid').innerHTML = checks.map(c => {
    const r = runState[c.id];
    return `<article class="check-card" id="check-${c.id}">
      <div class="check-top">
        <span class="check-icon">${c.icon}</span>
        <span class="check-state ${r?.pass ? 'pass' : r ? 'fail' : ''}">${r ? (r.pass ? 'Verified' : 'Needs attention') : 'Not run'}</span>
      </div>
      <div class="check-number">CHECK ${c.number}</div>
      <h3>${c.title}</h3>
      <p class="check-desc">${c.description}</p>
      <div class="check-rule"><span>TEST</span><strong>${c.method}</strong></div>
      <div class="check-rule"><span>EXPECT</span><strong>${c.success}</strong></div>
      ${r ? `<div class="result ${r.pass ? 'pass' : 'fail'}">
        <strong>${escapeHtml(r.summary)}</strong>
        <p>${escapeHtml(r.detail)}</p>
        <small>Checked ${new Date(checkedAt[c.id]).toLocaleTimeString()}</small>
      </div>` : ''}
      <p class="check-caveat">${c.caveat}</p>
      <div class="check-actions">
        <button class="button ${r ? 'secondary' : 'primary'} run-check" data-check="${c.id}" ${pendingChecks.has(c.id) || auditBusy ? 'disabled' : ''}>${pendingChecks.has(c.id) ? 'Checking…' : r ? 'Run again' : 'Run check'} ↗</button>
        ${c.id === 'trace' ? '<button class="button secondary" type="button" style="font-size:11px;padding:8px 10px;" onclick="viewPacketsGuide()">◈ Inspect Wire Packets (Task G)</button>' : ''}
        ${r ? `<details><summary>View command output</summary><pre>${escapeHtml(logState[c.id] || 'No output')}</pre></details>` : ''}
      </div>
    </article>`;
  }).join('');

  const passed = Object.values(runState).filter(x => x.pass).length;
  $('#verified-count').innerHTML = `${passed} <small>/ 8 checks</small>`;
  $('#audit-summary').textContent = Object.keys(runState).length ? `${Object.keys(runState).length} of 8 checks run this session` : 'No checks run this session';
  $('#export').disabled = !Object.keys(runState).length;
}

async function runCheck(id) {
  if (pendingChecks.has(id)) return;
  pendingChecks.add(id);
  const c = checks.find(x => x.id === id);
  const button = document.querySelector(`.run-check[data-check="${id}"]`);
  if (button) { button.disabled = true; button.textContent = 'Checking…'; }
  try {
    const data = c.id === 'lan'
      ? await Promise.all(['mac1', 'mac3', 'mac4', 'gateway'].map(t => api(`/api/ping?target=${t}`)))
      : await api(c.endpoint);
    const r = interpret(id, data);
    runState[id] = r;
    logState[id] = r.raw;
    checkedAt[id] = new Date().toISOString();
    renderChecks();
    return r;
  } catch (e) {
    runState[id] = { pass: false, summary: 'Check could not run', detail: e.message, raw: e.stack || e.message };
    logState[id] = e.stack || e.message;
    checkedAt[id] = new Date().toISOString();
    renderChecks();
    return runState[id];
  } finally { pendingChecks.delete(id); renderChecks(); }
}

async function runAll() {
  if (auditBusy || pendingChecks.size) return;
  auditBusy = true; renderChecks();
  const btn = $('#run-all');
  btn.disabled = true;
  const original = btn.innerHTML;
  for (const [i, c] of checks.entries()) {
    btn.textContent = `Running ${i + 1} of 8…`;
    await runCheck(c.id);
  }
  auditBusy = false; renderChecks();
  btn.disabled = false;
  btn.innerHTML = original;
  const passed = Object.values(runState).filter(x => x.pass).length;
  setNotice(`${passed} of 8 live checks verified. Open any result for its command output.`, passed === 8 ? 'success' : 'warn');
}

function renderEvidence() {
  const cats = [['all', 'All files'], ['lan', 'LAN'], ['dns', 'DNS'], ['load-balancing', 'Load balancing'], ['tls', 'TLS'], ['caching', 'Caching'], ['wireshark', 'Packets'], ['failures', 'Failures'], ['phase2', 'Phase 2']];

  // Update persona counts
  const personCounts = {
    all: files.length,
    A: files.filter(f => f.person === 'A').length,
    B: files.filter(f => f.person === 'B').length,
    C: files.filter(f => f.person === 'C').length,
    D: files.filter(f => f.person === 'D').length,
    COMBINED: files.filter(f => f.person === 'COMBINED').length
  };
  const countAll = $('#count-person-all'); if (countAll) countAll.textContent = personCounts.all;
  const countA = $('#count-person-a'); if (countA) countA.textContent = personCounts.A;
  const countB = $('#count-person-b'); if (countB) countB.textContent = personCounts.B;
  const countC = $('#count-person-c'); if (countC) countC.textContent = personCounts.C;
  const countD = $('#count-person-d'); if (countD) countD.textContent = personCounts.D;
  const countCombined = $('#count-person-combined'); if (countCombined) countCombined.textContent = personCounts.COMBINED;

  // Filter by person
  const personFiltered = selectedPerson === 'all'
    ? files
    : files.filter(f => f.person === selectedPerson);

  // Render category filters with dynamic counts based on person selection
  $('#evidence-filters').innerHTML = cats.map(([id, name]) => {
    const cCount = id === 'all' ? personFiltered.length : personFiltered.filter(f => f.category === id).length;
    return `<button class="filter ${filter === id ? 'active' : ''}" data-filter="${id}">${name} <span>${cCount}</span></button>`;
  }).join('');

  // Filter by category
  const shown = filter === 'all' ? personFiltered : personFiltered.filter(f => f.category === filter);

  $('#evidence-list').innerHTML = shown.length ? shown.map(f => {
    const personKey = (f.person || 'shared').toLowerCase();
    const pBadge = `<span class="badge-person ${personKey}">${escapeHtml(f.personName || `Person ${f.person}`)}</span>`;
    const catBadge = `<span class="badge-cat">${escapeHtml(f.category)}</span>`;
    const icon = /\.pcap/i.test(f.name) ? '◈' : /\.(png|jpe?g)$/i.test(f.name) ? '▧' : '▤';
    const kb = Math.max(1, Math.round(f.bytes / 1024));
    return `<button class="evidence-row" data-file="${escapeHtml(f.path)}">
      <span class="file-icon">${icon}</span>
      <span class="file-info">
        <div class="file-header-row">
          <strong>${escapeHtml(f.name)}</strong>
          ${pBadge}
          ${catBadge}
        </div>
        <small class="file-path">${escapeHtml(f.path)} · IP: ${escapeHtml(f.personIp || 'LAN')}</small>
      </span>
      <span class="file-meta">${kb} KB</span>
      <span class="file-open">Inspect ↗</span>
    </button>`;
  }).join('') : '<div class="empty-evidence"><strong>No saved files match the current filters.</strong><p>Try switching member or category tabs to inspect existing artifacts.</p></div>';

  const totalCategories = cats.length - 1;
  const covered = new Set(files.map(f => f.category)).size;
  $('#file-count').innerHTML = `${files.length} <small>files</small>`;
  $('#evidence-summary').textContent = `${covered} of ${totalCategories} evidence categories have files`;
  $('#evidence-coverage').textContent = `${covered}/${totalCategories} categories covered across 4 team machines`;
}

async function loadEvidence() {
  try {
    files = (await api('/api/evidence')).files;
    renderEvidence();
  } catch (e) {
    $('#evidence-list').textContent = 'Could not load evidence: ' + e.message;
  }
}

function showEvidence(file) {
  const d = $('#evidence-dialog');
  $('#evidence-title').textContent = file.name;
  $('#evidence-path').textContent = `${file.personName ? file.personName + ' · ' : ''}${file.path}`;
  $('#evidence-download').href = file.url;
  const output = $('#evidence-output');
  output.textContent = 'Loading…';
  d.showModal();
  if (/\.(txt|log|json|sh)$/i.test(file.name)) {
    fetch(file.url).then(r => r.text()).then(t => output.textContent = t).catch(e => output.textContent = e.message);
  } else if (/\.(png|jpe?g)$/i.test(file.name)) {
    output.innerHTML = `<img src="${file.url}" alt="${escapeHtml(file.name)}">`;
  } else {
    output.textContent = 'Binary capture or archive. Click "Open original ↗" below to download or inspect in Wireshark.';
  }
}

function renderPhase2Checks() {
  const grid = $('#phase2-grid');
  if (!grid) return;
  grid.innerHTML = phase2Checks.map(c => {
    const r = phase2State[c.ext];
    const busy = pendingPhase2.has(c.ext) || phase2AuditBusy;
    return `<article class="check-card" id="p2-check-${c.ext}">
      <div class="check-top">
        <span class="check-icon">${c.icon}</span>
        <span class="check-state ${r?.pass ? 'pass' : r ? 'fail' : ''}">${r ? (r.pass ? 'Verified' : 'Needs attention') : 'Not run'}</span>
      </div>
      <div class="check-number">${c.owner}</div>
      <h3>${c.title}</h3>
      <p class="check-desc">${c.desc}</p>
      <div class="check-rule"><span>CONFIG</span><strong>${c.rule}</strong></div>
      ${r ? `<div class="result ${r.pass ? 'pass' : 'fail'}">
        <strong>${escapeHtml(r.summary)}</strong>
        <p>${escapeHtml(r.detail)}</p>
      </div>` : ''}
      <p class="check-caveat">${c.caveat}</p>
      <div class="check-actions">
        <button class="button ${r ? 'secondary' : 'primary'} run-p2-check" data-p2="${c.ext}" ${busy ? 'disabled' : ''}>${pendingPhase2.has(c.ext) ? 'Checking…' : r ? 'Run again' : 'Run check'} ↗</button>
        ${r ? `<details><summary>View command output</summary><pre>${escapeHtml(r.raw || 'No output')}</pre></details>` : ''}
      </div>
    </article>`;
  }).join('');
}

async function runPhase2Check(ext) {
  if (pendingPhase2.has(ext)) return;
  pendingPhase2.add(ext);
  renderPhase2Checks();
  try {
    const res = await api(`/api/phase2-check?ext=${ext}`);
    phase2State[ext] = res;
    return res;
  } catch (e) {
    phase2State[ext] = { ext, pass: false, summary: 'Check could not run', detail: e.message, raw: e.stack || e.message };
    return phase2State[ext];
  } finally {
    pendingPhase2.delete(ext);
    renderPhase2Checks();
  }
}

async function runAllPhase2() {
  if (phase2AuditBusy || pendingPhase2.size) return;
  phase2AuditBusy = true;
  const btn = $('#run-phase2-all');
  const orig = btn ? btn.textContent : '';
  renderPhase2Checks();
  try {
    for (const [i, c] of phase2Checks.entries()) {
      if (btn) { btn.disabled = true; btn.textContent = `Running Ext ${c.ext} (${i + 1}/6)…`; }
      await runPhase2Check(c.ext);
    }
  } finally {
    phase2AuditBusy = false;
    if (btn) { btn.disabled = false; btn.textContent = orig; }
    renderPhase2Checks();
  }
  const passed = Object.values(phase2State).filter(x => x.pass).length;
  setNotice(`Phase 2 verification: ${passed} of 6 extensions verified locally.`, passed === 6 ? 'success' : 'warn');
}

async function switchLabMode(mode) {
  setNotice(mode === 'local' ? 'Starting local services (3001, 3002, 8443, 8444, 15353, 15354) and switching targets to 127.0.0.1…' : 'Switching probe targets to 4-Mac Team LAN IPs (10.7.17.94 / 10.7.29.79 / 10.7.30.144 / 10.7.22.227)…', 'info');
  try {
    const res = await apiPost('/api/phase2-ensure-local', { mode });
    config = res.config;
    renderConfig();
    runState = {}; logState = {}; phase2State = {}; renderChecks(); renderPhase2Checks();
    if ($('#config-dialog')?.open) $('#config-dialog').close();
    setNotice(mode === 'local'
      ? `1-Mac Local Mode active (127.0.0.1). All 6 local services ready${res.started?.length ? ` (started: ${res.started.join(', ')})` : ''}.`
      : '4-Mac Team LAN Mode active! Probes now target the 4 separate laptops directly.', 'success');
  } catch (err) {
    setNotice('Could not switch lab mode: ' + err.message, 'warn');
  }
}

function setup() {
  flowStep(-1);
  renderChecks();
  renderPhase2Checks();
  $('#failure-list').innerHTML = failures.map((f, i) =>
    `<details class="failure-item">
      <summary><span class="failure-num">0${i + 1}</span><strong>${f[0]}</strong><span>+</span></summary>
      <div>
        <p><b>Observe:</b> ${f[2]}</p>
        <p><b>Restore:</b> ${f[3]}</p>
        <div style="margin-top:12px;display:flex;gap:8px;align-items:center;">
          <button class="button primary" style="font-size:12px;padding:6px 12px;" onclick="setScenario('${f[1]}'); location.hash='#journey';">Play this explanation</button>
          <button class="button secondary" style="font-size:12px;padding:6px 12px;" onclick="setScenario('normal');">Play normal flow</button>
        </div>
      </div>
    </details>`
  ).join('');

  $('#apply-fault').addEventListener('click', applyFault);
  $('#play-flow').addEventListener('click', () => playFlow(false));
  $('#send-request').addEventListener('click', () => playFlow(true));
  $('#check-grid').addEventListener('click', e => {
    const b = e.target.closest('[data-check]');
    if (b) runCheck(b.dataset.check);
  });
  $('#run-all').addEventListener('click', runAll);
  $('#run-phase2-all')?.addEventListener('click', runAllPhase2);
  $('#phase2-grid')?.addEventListener('click', e => {
    const b = e.target.closest('[data-p2]');
    if (b) runPhase2Check(b.dataset.p2);
  });
  $('#btn-local-mode')?.addEventListener('click', () => switchLabMode('local'));
  $('#btn-lan-mode')?.addEventListener('click', () => switchLabMode('lan'));
  $('#inline-reset-lan')?.addEventListener('click', () => switchLabMode('lan'));
  $('#preset-local')?.addEventListener('click', () => switchLabMode('local'));
  $('#preset-lan')?.addEventListener('click', () => switchLabMode('lan'));
  $('#inline-ip-form')?.addEventListener('submit', async e => {
    e.preventDefault();
    const form = new FormData(e.target), update = {};
    for (const id of ['mac1', 'mac2', 'mac3', 'mac4', 'gateway']) update[id] = { ip: String(form.get(id) || '').trim() };
    try {
      const d = await apiPost('/api/config', update);
      config = d.config;
      renderConfig();
      runState = {}; logState = {}; phase2State = {}; renderChecks(); renderPhase2Checks();
      setNotice(`Saved live laptop IPs (${config.mac1.ip} · ${config.mac2.ip} · ${config.mac3.ip} · ${config.mac4.ip}). All probes now target these laptops!`, 'success');
    } catch (err) {
      setNotice('Invalid IP address: ' + err.message, 'warn');
    }
  });
  $('#refresh-evidence').addEventListener('click', loadEvidence);
  $('#persona-filters')?.addEventListener('click', e => {
    const b = e.target.closest('[data-person]');
    if (b) {
      selectedPerson = b.dataset.person;
      document.querySelectorAll('#persona-filters .persona-tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.person === selectedPerson);
      });
      renderEvidence();
    }
  });
  $('#evidence-filters').addEventListener('click', e => {
    const b = e.target.closest('[data-filter]');
    if (b) { filter = b.dataset.filter; renderEvidence(); }
  });
  $('#evidence-list').addEventListener('click', e => {
    const b = e.target.closest('[data-file]');
    if (b) {
      const f = files.find(x => x.path === b.dataset.file);
      if (f) showEvidence(f);
    }
  });
  $('#configure').addEventListener('click', () => $('#config-dialog').showModal());
  document.querySelectorAll('dialog .close,.close-config').forEach(b =>
    b.addEventListener('click', () => b.closest('dialog').close())
  );
  $('#config-form').addEventListener('submit', async e => {
    e.preventDefault();
    const form = new FormData(e.target), update = {};
    for (const id of ['mac1', 'mac2', 'mac3', 'mac4', 'gateway']) update[id] = { ip: form.get(id) };
    try {
      const d = await apiPost('/api/config', update);
      config = d.config;
      renderConfig();
      $('#config-dialog').close();
      runState = {};
      logState = {};
      renderChecks();
      setNotice('Probe targets saved. Run the checks again to verify the new addresses.', 'success');
    } catch (err) {
      $('#config-error').textContent = err.message;
    }
  });

  $('#export').addEventListener('click', () => {
    const payload = {
      exportedAt: new Date().toISOString(),
      configuration: config,
      checks: Object.fromEntries(checks.filter(c => runState[c.id]).map(c => [c.id, { ...runState[c.id], checkedAt: checkedAt[c.id], commandOutput: logState[c.id] }]))
    };
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }));
    a.download = 'network-lab-session-evidence.json';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });

  const navLinks = [...document.querySelectorAll('.sidebar nav a')];
  const observer = new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        navLinks.forEach(a => a.classList.toggle('active', a.hash === '#' + entry.target.id));
      }
    }
  }, { rootMargin: '-15% 0px -70% 0px' });
  document.querySelectorAll('main section[id]').forEach(s => observer.observe(s));

  // Wireshark live packet sniffer listeners
  $('#btn-start-capture')?.addEventListener('click', runPacketCapture);
  $('#btn-view-packets')?.addEventListener('click', e => {
    e.preventDefault();
    viewPacketsGuide();
  });
  $('#packet-filters')?.addEventListener('click', e => {
    const b = e.target.closest('[data-pfilter]');
    if (b) {
      activePacketFilter = b.dataset.pfilter;
      document.querySelectorAll('#packet-filters .filter').forEach(f => f.classList.toggle('active', f === b));
      renderPacketTable();
    }
  });
  $('#packet-tbody')?.addEventListener('click', e => {
    const tr = e.target.closest('tr[data-num]');
    if (tr) {
      const p = livePackets.find(x => x.num === Number(tr.dataset.num));
      if (p) showPacketDetail(p);
    }
  });
}

let livePackets = [];
let capturedInterface = '';
function packetMatches(p, filter) {
  const ports = [p.src.split(':').at(-1), p.dst.split(':').at(-1)];
  if (filter === 'ALL') return true;
  if (filter === 'DNS') return ports.includes('53') || p.protocol === 'DNS';
  if (filter === 'TLS') return ports.includes('8443') || p.protocol === 'TLS';
  if (filter === 'HTTP') return ports.some(port => ['8080','3001','3002'].includes(port)) || p.protocol === 'HTTP';
  if (filter === 'TCP') return p.protocol === 'TCP' || p.protocol === 'TLS' || p.raw.includes('Flags [');
  return p.protocol === filter;
}
let activePacketFilter = 'ALL';

function viewPacketsGuide() {
  const el = $('#packets');
  if (el) el.scrollIntoView({ behavior: 'smooth' });
}

function viewPhase2Evidence() {
  selectedPerson = 'all';
  filter = 'phase2';
  document.querySelectorAll('#persona-filters .persona-tab').forEach(tab => {
    tab.classList.toggle('active', tab.dataset.person === 'all');
  });
  renderEvidence();
  const el = $('#evidence');
  if (el) el.scrollIntoView({ behavior: 'smooth' });
}

async function runPacketCapture() {
  const btn = $('#btn-start-capture');
  const empty = $('#capture-empty');
  const loading = $('#capture-loading');
  const results = $('#capture-results');
  const statusText = $('#packet-status-text');
  const downloadBtn = $('#btn-download-pcap');

  if (empty) empty.style.display = 'none';
  if (results) results.style.display = 'none';
  if (loading) loading.style.display = 'flex';
  if (btn) btn.disabled = true;
  if (statusText) statusText.textContent = 'Detecting route interface and starting tcpdump…';

  try {
    const res = await apiPost('/api/capture-packets', {});
    livePackets = res.packets || [];
    capturedInterface = res.interface || 'en0 (Wi-Fi 10.7.29.79)';
    activePacketFilter = 'ALL';
    document.querySelectorAll('[data-pfilter]').forEach(b => b.classList.toggle('active', b.dataset.pfilter === 'ALL')); 

    if (loading) loading.style.display = 'none';
    if (results) results.style.display = 'flex';
    if (btn) {
      btn.disabled = false;
      btn.textContent = '↻ Capture again';
    }
    if (downloadBtn) {
      downloadBtn.href = res.pcapUrl;
      downloadBtn.style.display = 'inline-flex';
    }
    if (statusText) {
      statusText.textContent = `Parsed ${res.packetCount} IPv4 packet lines on ${capturedInterface} · Saved to ${res.pcapPath}`;
    }

    renderPacketTable();
    loadEvidence();
    setNotice(res.message + ` Saved to ${res.pcapPath}`, res.success ? 'success' : 'warn');
  } catch (err) {
    if (loading) loading.style.display = 'none';
    if (empty) empty.style.display = 'block';
    if (btn) btn.disabled = false;
    if (statusText) statusText.textContent = 'Capture failed: ' + err.message;
    setNotice('Packet capture failed: ' + err.message, 'error');
  }
}

function renderPacketTable() {
  const filtered = activePacketFilter === 'ALL'
    ? livePackets
    : livePackets.filter(p => packetMatches(p, activePacketFilter));

  $('#captured-count').textContent = livePackets.length;
  $('#count-all').textContent = livePackets.length;
  $('#count-dns').textContent = livePackets.filter(p => packetMatches(p, 'DNS')).length;
  $('#count-tcp').textContent = livePackets.filter(p => packetMatches(p, 'TCP')).length;
  $('#count-tls').textContent = livePackets.filter(p => packetMatches(p, 'TLS')).length;
  $('#count-http').textContent = livePackets.filter(p => packetMatches(p, 'HTTP')).length;

  const tbody = $('#packet-tbody');
  if (!tbody) return;

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:24px;color:#64748b;">No packets match the filter "${activePacketFilter}".</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(p =>
    `<tr data-num="${p.num}">
      <td><strong>${p.num}</strong></td>
      <td>${escapeHtml(p.time)}</td>
      <td><code>${escapeHtml(p.src)}</code></td>
      <td><code>${escapeHtml(p.dst)}</code></td>
      <td><span class="badge-proto proto-${escapeHtml(p.protocol.toLowerCase())}">${escapeHtml(p.protocol)}</span></td>
      <td>${p.length || '-'}</td>
      <td>${escapeHtml(p.info)}</td>
    </tr>`
  ).join('');

  if (filtered.length > 0) {
    showPacketDetail(filtered[0]);
  }
}

function showPacketDetail(p) {
  document.querySelectorAll('#packet-tbody tr').forEach(tr => {
    tr.classList.toggle('selected', Number(tr.dataset.num) === p.num);
  });
  const label = $('#inspector-frame-label');
  const content = $('#inspector-content');
  if (label) label.textContent = `Frame #${p.num} · Protocol: ${p.protocol} · Reported transport length: ${p.length}B · ${p.src} ➔ ${p.dst}`;
  if (content) {
    content.textContent = `FRAME #${p.num} DECODED DETAILS:
--------------------------------------------------------------------------------
Timestamp:       ${p.time}
Interface:       ${capturedInterface} · Link-layer: Ethernet (DLT_EN10MB)
Layer 3 (Net):   IPv4 Source ${p.src.split(':')[0]} ➔ Destination ${p.dst.split(':')[0]}
Layer 4 (Trans): ${p.protocol === 'TCP' || p.protocol === 'TLS' ? 'TCP' : 'UDP / port-based classification'} Source Port ${p.src.split(':')[1]} ➔ Destination Port ${p.dst.split(':')[1]}
Protocol badge:  ${p.protocol}
Summary:         ${p.info}
Application payloads and TLS details must be inspected in the pcap.

RAW TCPDUMP CAPTURE LINE:
${p.raw}`;
  }
}

async function init() {
  setup();
  try {
    config = await api('/api/config');
    renderConfig();
    const faultInfo = await api('/api/fault');
    liveFault = faultInfo.fault || 'normal';
    $('#scenario-scope').textContent = faultInfo.message;
    setNotice(faultInfo.fault === 'normal' ? 'Ready to explore. Live checks run from the machine hosting this dashboard.' : `Active Fault: ${faultInfo.message}`, faultInfo.fault === 'normal' ? 'info' : 'warn');
  } catch (e) {
    setNotice('Could not load network configuration: ' + e.message, 'warn');
    $('#run-all').disabled = true;
  }
  loadEvidence();
}

document.addEventListener('DOMContentLoaded', init);

