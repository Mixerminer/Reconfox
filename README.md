<div align="center">
  <img src="Reconfox.svg" alt="Reconfox logo" width="400"/>
  <h1>Reconfox</h1>
  <p>
    <em>A concurrent, modular, fault‑tolerant reconnaissance engine.</em>
  </p>
  <p>
    <img src="https://img.shields.io/badge/version-2.0.0-orange?style=flat-square" alt="version"/>
    <img src="https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square" alt="Python"/>
    <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="license"/>
    <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20win-lightgrey?style=flat-square" alt="platform"/>
  </p>
</div>

---

## Why Reconfox?

Most recon tools are single scripts; Reconfox is an **engine**:

- **⚙️ Concurrent core** – thread pools for DNS/HTTP, `asyncio` for TCP port sweeps. Hundreds of probes with zero busy‑waiting.
- **🧩 Modular pipeline** – six isolated stages (DNS → passive subs → active subs → ports → dirs → fingerprint) orchestrated by a queue. Each stage can be toggled independently.
- **🛡️ Fault‑tolerant** – a failing source (rate‑limited API, dropped socket) is logged and skipped; one stage never kills the whole run.
- **🕸️ Wildcard filtering** – resolves a random garbage host first; subdomains resolving to the wildcard IP are discarded – the #1 thing amateur tools miss.
- **🎯 Soft‑404 aware** – dir fuzzer baselines a random nonexistent path to distinguish real content from lenient servers.
- **📊 Structured output** – every finding is a typed, timestamped, severity‑scored record → JSON, plus a standalone HTML report.
- **🖥️ Live dashboard** – real‑time Rich TUI showing pipeline status and a live findings feed.

---

## Installation

```bash
git clone https://github.com/Mixerminer/Reconfox.git
cd Reconfox
pip install -e .
reconfox --version
```

---

Usage

```bash
# Full pipeline, top‑100 ports, 60 threads, HTML report
reconfox scan example.com -p top100 -t 60 --html report.html

# Aggressive subdomain discovery with a big wordlist
reconfox scan example.com --subs both -w /path/to/subdomains.txt

# Custom ports, no dir fuzzing, plain output for CI
reconfox scan example.com -p "22,80,443,8000-8100" --no-dirs --no-tui -o ci.json

# Generate HTML report from existing JSON
reconfox report reconfox_results.json -o scan.html
```

Options

Flag Default Description
--subs both Subdomain discovery: passive, active, both, off
-w, --wordlist packaged Wordlist for active subdomain brute‑force
-d, --dirlist packaged Wordlist for directory fuzzing
-p, --ports top100 top100, all, or custom spec like "22,80,8000-8100"
-t, --threads 40 Number of worker threads
--timeout 10.0 Per‑operation timeout (seconds)
--no-ports, --no-dirs, --no-fingerprint, --no-dns – Disable individual stages
-o, --output reconfox_results.json JSON output path
--html – Also generate a styled HTML report
--no-tui – Plain line output (for CI/scripts)

---

Project Structure

```
Reconfox/
├── setup.py
├── requirements.txt
├── README.md
└── reconfox/
    ├── __init__.py
    ├── __main__.py
    ├── cli.py
    ├── banner.py
    ├── config.py
    ├── pipeline.py
    ├── models.py
    ├── utils.py
    ├── data/
    │   ├── subdomains.txt
    │   └── dirs.txt
    ├── modules/
    │   ├── dns_resolver.py
    │   ├── subdomain_passive.py
    │   ├── subdomain_active.py
    │   ├── port_scanner.py
    │   ├── dir_fuzzer.py
    │   ├── tech_fingerprint.py
    │   └── report.py
    └── tui/
        ├── theme.py
        └── dashboard.py
```

---

Pipeline Flow

The engine runs six stages in order, each emitting findings into a shared queue. The TUI consumes events live while the pipeline continues.

1. DNS – resolves A, AAAA, MX, NS, TXT, SOA records.
2. Passive subdomains – collects from crt.sh, HackerTarget, RapidDNS, OTX.
3. Active subdomains – brute‑forces with wildcard filtering.
4. Port scanning – asynchronous TCP sweep with banner grabbing.
5. Directory fuzzing – soft‑404 aware content discovery.
6. Technology fingerprint – header/cookie/HTML signature detection.

Stages marked --no-* are skipped. Any stage error is a soft failure – the pipeline continues.

---

Live TUI

· Pipeline panel – shows each stage status: running ✔ done ✘ error – skipped
· Findings feed – rolling list of latest findings with severity colors
· Header bar – target, running finding/error counters

Palette: ember orange accents on warm brown, with spring‑green for success.

---

Reports

The --html flag generates a fully standalone HTML file – no CDN, no JavaScript, embedded CSS only. It includes:

· Ember‑themed header with target, scan stats, and creator credits
· Summary cards (findings / critical / high / soft errors / scan time)
· Findings grouped by type in sortable tables with severity badges
· Soft‑error section for transparency

Opens offline in any browser, ready for client reports.

---

Extending Reconfox

Add a new module by dropping a file into reconfox/modules/ with this interface:

```python
class MyModule:
    name = "mymodule"

    def __init__(self, ctx: ScanContext, ...) -> None:
        ...

    def run(self) -> int:
        # Emit findings:
        self.ctx.add(Finding(self.name, "type", value, ...))
        # Soft‑fail:
        self.ctx.error("reason")  # run continues
        return 0
```

Then register a _stage_<name> method in pipeline.py and add the stage to STAGE_ORDER in tui/dashboard.py. The TUI, JSON output, and HTML report will pick it up automatically.

---

Roadmap

☑ Concurrent pipeline core
☑ Live TUI dashboard
☑ HTML report renderer
☑ Packaged wordlists
☐ --proxy (Burp/ZAP) support
☐ Multi‑domain scope files
☐ ASN & CIDR expansion module
☐ Web cache / takeover checks

---

License & Disclaimer

MIT License. Use only on assets you are authorized to test.

Crafted by MixerMiner, Anonymous‑beta, samuelanih043‑droid.
