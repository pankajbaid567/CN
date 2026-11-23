# Person B — Mac 2: Complete Study & Evaluation Guide
**Candidate:** Ashutosh Singh  
**Role:** Edge Reverse Proxy, TLS Termination, Load Balancer & High Availability Lead  
**Assigned Hardware:** Mac 2 (`10.7.3.128`)

---

## 1. Executive Summary & Architecture

Person B (Mac 2) acts as the **central front door (Edge Proxy)** for the entire 4-laptop Private Network Service Platform. Every client request originating from any machine on the Wi-Fi network hits Mac 2 first.

```
                           [ Clients / Browsers ]
                                     │
                 DNS: app.teamX.test │ Resolves to 10.7.3.128 (Mac 2)
                                     ▼
                     ┌───────────────────────────────┐
                     │       PERSON B — MAC 2        │
                     │          (10.7.3.128)         │
                     │                               │
                     │  ┌─────────────────────────┐  │
                     │  │      Nginx (Edge)       │  │
                     │  │   Ports: 8080 & 8443    │  │
                     │  └────────────┬────────────┘  │
                     │               │               │
                     │  • TLS/HTTPS Termination      │
                     │  • Custom Root CA & SAN Cert  │
                     │  • L7 Round-Robin Balancing   │
                     │  • Passive Health Checks      │
                     │  • X-Edge Header Injection    │
                     └───────────────┬───────────────┘
                                     │
                     ┌───────────────┴───────────────┐
                     │ Unencrypted HTTP Proxy (LAN)  │
                     ▼                               ▼
       ┌───────────────────────────┐   ┌───────────────────────────┐
       │     PERSON C — MAC 3      │   │     PERSON D — MAC 4      │
       │        (10.7.6.84)        │   │       (10.7.17.147)       │
       │                           │   │                           │
       │   Backend A (Express)     │   │   Backend B (Express)     │
       │        Port 3001          │   │        Port 3002          │
       └───────────────────────────┘   └───────────────────────────┘
```

### Why Mac 2 Exists (The "Cloud Equivalent")
In real-world cloud architectures (AWS / GCP / Cloudflare), backends are never directly exposed to the internet. Instead, an **Application Load Balancer (ALB)** or **API Gateway** sits at the perimeter. Mac 2 fulfills this exact role:
1. **Security Isolation:** Clients never know the backends' IP addresses or internal ports (`3001` / `3002`).
2. **Centralized TLS Management:** Certificates exist solely on the Edge; individual backend microservices don't need complex crypto overhead.
3. **Traffic Distribution:** Requests are evenly divided across servers.
4. **Fault Tolerance:** If a backend crashes, Mac 2 reroutes requests seamlessly without the end user noticing an error.

---

## 2. Phase 1 Responsibilities & Technical Mechanics

### Task D: Reverse Proxy & Round-Robin Load Balancing
- **Nginx Configuration:** `personB/nginx/nginx.conf`
- **Upstream Pool:**
  ```nginx
  upstream backend_pool {
      server 10.7.6.84:3001 max_fails=3 fail_timeout=5s;   # Backend A (Mac 3)
      server 10.7.17.147:3002 max_fails=3 fail_timeout=5s; # Backend B (Mac 4)
  }
  ```
- **Balancing Mechanism:** Standard Round-Robin. Request #1 is dispatched to Backend A, Request #2 to Backend B, Request #3 to Backend A, and so on.
- **Header Forwarding:** Nginx acts as a reverse proxy, rewriting and injecting necessary HTTP headers so backends understand the real client context:
  ```nginx
  proxy_set_header Host $host;                          # Preserves original domain name
  proxy_set_header X-Real-IP $remote_addr;              # Actual client IP address
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;           # Tells backend if client used HTTP or HTTPS
  proxy_pass_header X-Backend;                          # Forwards backend origin identity (A or B)
  proxy_pass_header Cache-Control;                      # Passes RFC 9111 caching headers
  proxy_pass_header ETag;                               # Passes HTTP 304 validation fingerprints
  proxy_buffering off;                                  # Immediate transmission without buffering delays
  ```

---

### Task E: TLS/HTTPS Termination & Custom Root CA

Person B is solely responsible for cryptographic security across the cluster.

#### 1. Why `curl -k` (Insecure Mode) Was Strictly Forbidden
The evaluation rules required real, cryptographically validated HTTPS without using the `-k` (`--insecure`) flag. Anyone can create an unverified self-signed certificate, but real browsers and security scanners reject them.

#### 2. The 2-Tier PKI Hierarchy Built by Person B
To achieve trusted HTTPS on private `.test` domains, Person B created a private **Public Key Infrastructure (PKI)**:
1. **Root Certificate Authority (CA):**
   - Private Key: `personB/tls/ca.key` (2048-bit RSA)
   - Self-Signed CA Cert: `personB/tls/ca.crt` (Subject: `/CN=TeamX Local CA`)
   - Distributed to all 4 laptops and installed into macOS System Keychain with `trustRoot` privileges.
2. **Leaf (Server) Certificate:**
   - Private Key: `personB/tls/server.key` (2048-bit RSA)
   - Certificate Signing Request (CSR): `personB/tls/server.csr`
   - Signed by `ca.crt` with a 365-day validity.

#### 3. Subject Alternative Name (SAN) Configuration (`server.ext`)
Modern browsers (Chrome, Safari) and `curl` completely ignore the deprecated `Common Name (CN)` field and reject any certificate lacking valid **SAN** records. Person B authored `personB/tls/server.ext`:
```ini
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = app.teamX.test
DNS.2 = api.teamX.test
DNS.3 = localhost
IP.1 = 127.0.0.1
```

#### 4. Nginx TLS Termination Directives
```nginx
server {
    listen 8443 ssl;
    server_name localhost app.teamX.test api.teamX.test;

    ssl_certificate     ../tls/server.crt;
    ssl_certificate_key ../tls/server.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ...
}
```
* **TLS Termination Process:** Client and Mac 2 execute a TLS handshake on port `8443`. Mac 2 decrypts the traffic using `server.key`. Nginx then speaks plain HTTP (`3001`/`3002`) across the internal LAN to Mac 3 and Mac 4.

---

## 3. Phase 2 Responsibilities & High Availability

In Phase 2, Person B led **Extension D (High Availability & Passive Failover)** and enabled **Extension E (Standby Edge Cutover)**.

### Extension D: High Availability & Passive Failover
- **Problem Statement:** If Backend A crashes or is turned off, will the client receive an error?
- **Person B's Solution:** Configured passive health detection and upstream retries:
  ```nginx
  proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
  proxy_next_upstream_tries 2;
  proxy_connect_timeout 1s;
  proxy_read_timeout 2s;
  ```
- **How It Operates Live:**
  1. Client sends request to `https://app.teamX.test:8443/api/status`.
  2. Nginx forwards to Backend A (`10.7.6.84:3001`).
  3. If Backend A's process is down, the OS returns TCP `RST` (connection refused).
  4. Rather than returning an error to the user, `proxy_next_upstream` immediately intercepts the failure and replays the request against Backend B (`10.7.17.147:3002`).
  5. The client receives `200 OK` from Backend B with **zero dropped requests**.
  6. After 3 consecutive failures (`max_fails=3`), Nginx temporarily blacklists Backend A for 5 seconds (`fail_timeout=5s`).
  7. Once Backend A restarts and 5s elapse, Nginx automatically probes it again and restores full round-robin traffic!

---

### Extension E: Edge Provenance & Single Point of Failure (SPOF)
- **The Critical SPOF Concept:**
  Even though backends are redundant (Extension D), **Mac 2 is still a Single Point of Failure!** If Mac 2 runs out of battery or loses Wi-Fi, the entire system is inaccessible.
- **Person B's Architecture for Disaster Recovery:**
  1. Person B added edge identification header to `phase2/personB/nginx/nginx-primary-lan.conf`:
     ```nginx
     add_header X-Edge "Primary-Mac2" always;
     ```
  2. Person B shared the TLS certificate bundle and provided the standby configuration (`phase2/personC/nginx/nginx-standby-lan.conf`) for Mac 3.
  3. When Mac 2 goes offline, Person A updates DNS from `10.7.3.128` (Mac 2) → `10.7.6.84` (Mac 3).
  4. The client's response header cleanly changes from:
     `X-Edge: Primary-Mac2`  ➔  `X-Edge: Standby-Mac3`
     proving seamless disaster recovery.

---

## 4. Person B File Map & Directory Structure

```
CN/
├── personB/
│   ├── README.md                      # Overview of Person B duties
│   ├── nginx/
│   │   ├── nginx.conf                 # Phase 1 standalone configuration
│   │   ├── start_nginx.sh             # Management script (test, start, stop, reload)
│   │   └── logs/                      # Access and error logs
│   └── tls/
│       ├── generate_cert.sh           # Automated PKI generation script
│       ├── ca.key & ca.crt            # Root Certificate Authority
│       ├── server.key & server.crt    # Leaf TLS cert for app.teamX.test
│       ├── server.csr                 # Certificate Signing Request
│       └── server.ext                 # OpenSSL v3 extension config for SANs
└── phase2/
    └── personB/
        ├── README.md                  # Phase 2 Person B execution guide
        └── nginx/
            ├── nginx-primary-lan.conf # 4-Mac LAN config (HA upstream + X-Edge)
            └── nginx-local-primary.conf# 1-Mac local testing config
```

---

## 5. Exact Terminal Commands to Run (Cheat Sheet)

### Step 1: Manage TLS Certificates & Trust Store
```bash
# Verify certificate Subject, Issuer, Validity and SANs:
openssl x509 -in personB/tls/server.crt -text -noout | grep -E "Issuer:|Subject:|DNS:"

# Add CA to macOS System Keychain (trustRoot):
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain personB/tls/ca.crt

# Verify CA installation in macOS Keychain:
security find-certificate -c "TeamX Local CA" /Library/Keychains/System.keychain
```

### Step 2: Start and Manage Nginx
```bash
# --- PHASE 1 NGINX ---
./personB/nginx/start_nginx.sh test       # Test config syntax
./personB/nginx/start_nginx.sh start      # Start daemon
./personB/nginx/start_nginx.sh status     # Check PID and listening ports
./personB/nginx/start_nginx.sh stop       # Stop daemon

# --- PHASE 2 NGINX (4-Mac LAN Mode) ---
mkdir -p phase2/personB/nginx/logs

# 1. Test syntax
nginx -p "$(pwd)/phase2/personB/nginx" -c "$(pwd)/phase2/personB/nginx/nginx-primary-lan.conf" -t

# 2. Start Phase 2 Primary Edge
nginx -p "$(pwd)/phase2/personB/nginx" -c "$(pwd)/phase2/personB/nginx/nginx-primary-lan.conf"

# 3. Stream access and error logs live during testing:
tail -f phase2/personB/nginx/logs/primary-lan-access.log
tail -f phase2/personB/nginx/logs/primary-lan-error.log

# 4. Stop Nginx cleanly:
nginx -p "$(pwd)/phase2/personB/nginx" -c "$(pwd)/phase2/personB/nginx/nginx-primary-lan.conf" -s stop
```

### Step 3: Verify Everything from the Terminal
```bash
# 1. Test HTTPS connection with full TLS handshake trace:
curl -v --cacert personB/tls/ca.crt "https://app.teamX.test:8443/api/status"

# 2. Test Round-Robin distribution (Observe alternating X-Backend: A and B):
for i in {1..6}; do
    curl -sI "https://app.teamX.test:8443/api/status" | grep -iE "HTTP/|X-Backend|X-Edge"
done

# 3. Test HTTP 304 Caching validation:
curl -i "https://app.teamX.test:8443/api/cached"
# Copy ETag from output, then run:
curl -i -H 'If-None-Match: "<PASTED_ETAG>"' "https://app.teamX.test:8443/api/cached"
# Should return HTTP/1.1 304 Not Modified with zero content length!
```

---

## 6. Top Viva Voce Questions & High-Scoring Answers

### Q1: What does "TLS Termination" mean and why do it at Nginx instead of each backend?
**Answer:**  
TLS Termination means Nginx decrypts incoming HTTPS traffic from the client on port `8443`, inspects the plaintext HTTP request, and forwards it to Backend A or B over plain HTTP (`3001`/`3002`).  
**Why at Nginx?**
1. **Centralized Certificate Management:** Certificates are installed in only one place. When certs expire, we only update Nginx, not dozens of microservices.
2. **Performance:** Asymmetric cryptography (RSA/ECDHE) is CPU-heavy. Offloading it to Nginx frees up application servers to execute business logic.
3. **Layer 7 Inspection:** Nginx must decrypt the packet to read HTTP headers, URL routes, cookies, and perform intelligent routing or caching.

---

### Q2: Why wasn't `curl -k` allowed, and how did you establish native trust?
**Answer:**  
`curl -k` tells the client to bypass certificate validation, making the connection vulnerable to Man-in-the-Middle (MITM) attacks.  
To achieve native trust:
1. We acted as our own Certificate Authority (CA) by creating `ca.crt`.
2. We imported `ca.crt` into macOS System Keychain under `/Library/Keychains/System.keychain` using `security add-trusted-cert -d -r trustRoot`.
3. When `curl` initiates the TLS handshake, it validates Nginx's `server.crt` against the trusted Root CA in the Keychain and verifies the domain matches the SAN. As a result, HTTPS connects with **zero warnings**.

---

### Q3: What is a SAN (Subject Alternative Name) and why did OpenSSL require `server.ext`?
**Answer:**  
Historically, SSL certificates used the `Common Name (CN)` field in the Subject line (e.g. `CN=app.teamX.test`). However, RFC 2818 and modern browsers deprecated CN due to ambiguity and lack of support for multiple hostnames.  
Modern TLS requires **SAN (`subjectAltName`)**, which explicitly enumerates all valid hostnames (`DNS.1 = app.teamX.test`, `DNS.2 = api.teamX.test`, `IP.1 = 127.0.0.1`). Without SAN in `server.ext`, Chrome and modern `curl` immediately fail with `SSL_ERROR_BAD_CERT_DOMAIN`.

---

### Q4: How does Nginx know a backend has died in Extension D, and what does `proxy_next_upstream` do?
**Answer:**  
Nginx uses **passive health checks**:
- In `upstream backend_pool`, we specify `max_fails=3 fail_timeout=5s`.
- When Nginx forwards a request to Backend A and the connection is refused or times out, Nginx records 1 failure.
- Because `proxy_next_upstream error timeout http_502;` is enabled with `proxy_next_upstream_tries 2;`, Nginx **instantly retries the identical request on Backend B** before sending any reply to the client.
- The end user gets a clean `200 OK` with 0 dropped packets. After 3 failures, Backend A is marked inactive for 5 seconds.

---

### Q5: What is the difference between active and passive health checks in Nginx?
**Answer:**  
- **Passive Health Checks (Open-Source Nginx):** Nginx does not proactively ping backends. It only detects a backend is down when an actual client request fails, after which it retries on another upstream and temporarily marks the server down.
- **Active Health Checks (Nginx Plus / Commercial):** Nginx periodically generates background HTTP probes (e.g., `GET /health` every 2 seconds) independent of client traffic.

---

### Q6: What single point of failure (SPOF) remains after Extension D, and how is it resolved in Extension E?
**Answer:**  
Even with redundant backends, **Mac 2 (Nginx Edge) itself is a Single Point of Failure**. If Mac 2's hardware, OS, or Wi-Fi fails, neither backend can be reached.  
**Resolution in Extension E:** We maintain a **Standby Edge** on Mac 3 (`10.7.6.84`). If Mac 2 fails, DNS is updated so `app.teamX.test` points to Mac 3. In enterprise networks, this is automated using **VRRP (Virtual Router Redundancy Protocol)** or Keepalived with a floating Virtual IP (VIP).

---

### Q7: Why do we pass `proxy_set_header X-Real-IP $remote_addr;`?
**Answer:**  
Without reverse proxy headers, the backend application sees every incoming TCP connection as originating from Mac 2 (`10.7.3.128`) instead of the actual client laptop. Setting `X-Real-IP` and `X-Forwarded-For` preserves the true client identity for logging, security audits, and rate limiting.

---

### Q8: What causes an HTTP `502 Bad Gateway` vs `504 Gateway Timeout`?
**Answer:**  
- **`502 Bad Gateway`:** Nginx reached the backend IP, but the backend actively rejected the connection (e.g. Node.js process stopped, TCP `RST`), or returned an invalid HTTP response.
- **`504 Gateway Timeout`:** Nginx attempted to connect or wait for a response from the backend, but the backend failed to reply within `proxy_connect_timeout` (1s) or `proxy_read_timeout` (2s), often due to firewall packet dropping or an infinite loop in backend code.

---

### Q9: What happens during the TLS 1.2 handshake on port 8443?
**Answer:**  
1. **ClientHello:** Client sends supported cipher suites, TLS version, and SNI (`app.teamX.test`).
2. **ServerHello:** Nginx selects the best cipher suite (e.g. `ECDHE-RSA-AES256-GCM-SHA384`).
3. **Certificate:** Nginx presents `server.crt`.
4. **ServerKeyExchange & ServerHelloDone:** Diffie-Hellman parameters exchanged.
5. **ClientKeyExchange:** Symmetric session key negotiated.
6. **ChangeCipherSpec & Finished:** Encrypted communication begins; HTTP payload is transmitted.

---

### Q10: What is SNI (Server Name Indication) and why is it needed?
**Answer:**  
SNI is a TLS extension where the client specifies which hostname it wants to connect to during the initial `ClientHello`, *before* the TLS handshake completes. This allows one single Nginx IP address on port `8443` to host multiple secure domains with different SSL certificates (e.g., `app.teamX.test` vs `example.com`).

---

## 7. Fast Troubleshooting Checklist for Person B

| Symptom | Probable Cause | Fix |
| :--- | :--- | :--- |
| `nginx: [emerg] bind() to 0.0.0.0:8080 failed (48: Address already in use)` | Another Nginx or process is running on port 8080 | Run `lsof -i :8080` and kill old PID: `sudo kill -9 <PID>` |
| `curl: (60) SSL certificate problem: unable to get local issuer certificate` | Root CA (`ca.crt`) is not trusted in macOS Keychain | Run `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain personB/tls/ca.crt` |
| `curl: (60) SSL: certificate subject name does not match target host name` | Missing SAN in certificate | Regenerate cert using `server.ext` with `DNS.1 = app.teamX.test` |
| `502 Bad Gateway` | Both backends (3001 & 3002) are down or firewall is dropping | Check Mac 3 (`npm run start:a`) and Mac 4 (`npm run start:b`) |
| Nginx test fails: `cannot load certificate` | Wrong relative path to `server.crt` in Nginx config | Check path in config relative to Nginx prefix directory (`-p`) |
