# Deliberately vulnerable sample

A tiny application written **to be insecure**, so there is something to scan
when trying VulnScan AI out. Every file contains textbook vulnerabilities,
marked with comments.

**Never run or deploy this code.** It exists only to be read by the scanner.

| File | What is wrong with it |
| --- | --- |
| `app.py` | SQL injection, OS command injection, path traversal |
| `config.py` | Hardcoded credentials, debug mode left on |
| `web/server.js` | `eval` of request input, reflected XSS |

To scan it: zip this folder and upload the archive on the *New scan* page, or
paste one of the files there. `python -m scripts.seed_demo` (see the project
README) records a finished scan of these files without needing the model.
