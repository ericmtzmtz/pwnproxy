# Scanners

All scanners are HookBus consumers: they listen for `"done"` events published by the proxy addon pipeline, extract injection points (query params, form body, JSON body, cookies, headers), and perform automated testing with per-host rate limiting and result dedup.

| Scanner | Detection Methods | Injection Points | Key Features |
|---------|------------------|------------------|--------------|
| **SQLi** | Error-based (5 DBMS), Time-based blind | Query, Form, JSON, Cookies, Headers | DBMS fingerprinting, confirmed/tentative confidence |
| **XSS** | Reflected (probe + canary + context analysis), Stored (canary DB) | Query, Form, JSON, Cookies, Headers | 7 reflection contexts, stored XSS across requests |
| **LFI** | Content-based (OS file signatures) | Query, Form, JSON, Cookies, Headers | OS fingerprinting, PHP wrappers, null byte |
| **XXE** | Error-based, XInclude bypass, JSON mutation, OOB callback | Query, Form, JSON, Cookies, Headers | XML/JSON filtering, DOCTYPE bypass, OOB exfil |
| **SSRF** | OOB callback (internal callback server) | URL-like params, Redirect params | Smart param extraction, redirect detection |

## SQLi Scanner

- **Detection**: Error-based using regex signatures for MySQL, PostgreSQL, MSSQL, SQLite, and Oracle. Time-based blind using `SLEEP()`, `pg_sleep()`, `WAITFOR DELAY`, `DBMS_PIPE.RECEIVE_MESSAGE`, and `randomblob()` with latency thresholds (>4s primary, >2.4s confirmation).
- **Injection points**: All 5 locations (query, form body, JSON, cookies, headers).
- **Dedup**: By `(method, host+path, param_name, location)`.
- **Rate limiting**: Global semaphore (5), per-host semaphore (2), 100ms inter-request delay.

## XSS Scanner

- **Detection**: Reflected — probes with `pwnxss-probe`, detects reflection, analyzes context (html_body, html_attr, js_string, url, html_comment, svg_namespace, unknown), and selects context-specific payloads. Stored — injects canaries into SQLite database, scans every response for previously injected canaries.
- **Payload contexts**: `<script>` tags, event handlers, attr breakouts, JS template literals, `javascript:` URIs, `data:` URIs, comment breakouts, SVG `onbegin`/`onload`.
- **Dedup**: By `(method, host+path, param_name, location)`.

## LFI Scanner

- **Detection**: Replays payloads across multiple HTTP methods. Scans response for OS-specific patterns — Unix (`/etc/passwd`, `/bin/bash`), Windows (`win.ini` sections, `boot.ini`), PHP (`php://filter/base64`).
- **Payloads**: Path traversal (`../../../../etc/passwd`), null byte truncation (`%00`), PHP wrappers (`php://filter/read=convert.base64-encode/resource=...`).
- **Dedup**: By `(host+path, param_name, location)`.

## XXE Scanner

- **Detection**: Error-based (DOCTYPE with local file entities, XML parser error detection), XInclude bypass (`<xi:include>` when DOCTYPE blocked), JSON-to-XML mutation (for `application/json` endpoints), OOB (parameter entity callback to configured domain).
- **Scannable content types**: XML (`text/xml`, `application/xml`, etc.) and `application/json`.
- **Dedup**: By `(host+path, param_name, location)`.

## SSRF Scanner

- **Detection**: Smart parameter extraction by name (url, uri, redirect, callback, webhook, fetch, proxy, target, host, domain, page, resource, source) and redirect param detection (params reflected in `Location` headers of 3xx responses). Injects unique canary URLs pointing to an internal `CallbackServer`. A background task polls for hits and escalates severity from low to critical.
- **Infrastructure**: Built-in FastAPI-based callback listener on configurable host:port.
- **Dedup**: By `(host+path, param_name, location)`.
