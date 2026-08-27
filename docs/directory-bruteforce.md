# Directory Discovery (Bruteforce)

Wordlist-based path and file discovery via the Web UI or REST API.

## Built-in Wordlists

| Wordlist | Entries | Composition |
|----------|---------|-------------|
| `small` | 368 | Core pentest paths: admin panels, common files, API endpoints, config backups |
| `medium` | 3,137 | Small + combinatorial (roots × suffixes) + framework paths (WordPress, Django, Laravel) + date/number patterns + admin variants + API paths |
| `large` | 7,780 | Medium + Drupal/Joomla/Magento/Exchange/WebLogic/CGI paths + extended combinatorial (only-roots × only-suffixes) |

All wordlists are hand-curated for legal penetration testing. They are **not** exhaustive (no full raft/dirb busting) — for comprehensive discovery, supply your own via the custom wordlist option.

## Features

- **Soft-404 Detection** — Learns custom 404 page signatures by probing random non-existent paths, then filters false positives from results
- **Custom Extensions** — Append `.php`, `.html`, `.txt`, etc. to each wordlist entry
- **Scope Enforcement** — Only tests URLs matching the active session scope
- **Live Results** — Hits appear in real-time in the Discovered URLs dashboard

## API

```bash
# Start bruteforce
curl -X POST http://127.0.0.1:8000/api/v1/bruteforce/start \
  -H 'Content-Type: application/json' \
  -d '{"base_urls": ["https://target.com"], "wordlist": "medium", "detect_soft404": true}'

# List available wordlists
curl http://127.0.0.1:8000/api/v1/bruteforce/wordlists

# Stop
curl -X POST http://127.0.0.1:8000/api/v1/bruteforce/stop
```

Bruteforce jobs are tracked as tasks with the formal job state machine (`RUNNING → STOPPING → CANCELLED` on stop; stats include `probed`, `found`, `soft404_filtered`, `maxed`).
