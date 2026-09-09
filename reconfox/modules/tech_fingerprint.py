"""HTTP technology fingerprinting: headers, cookies, HTML signatures, Wappalyzer-style rules."""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..models import Finding, ScanContext
from ..utils import build_client

SIGNATURES: list[tuple[str, str, re.Pattern]] = [
    ("server", "nginx", re.compile(r"nginx", re.I)),
    ("server", "apache", re.compile(r"apache", re.I)),
    ("server", "iis", re.compile(r"microsoft-iis", re.I)),
    ("server", "cloudflare", re.compile(r"cloudflare", re.I)),
    ("header", "express", re.compile(r"^x-powered-by:.*express", re.I | re.M)),
    ("header", "php", re.compile(r"^x-powered-by:.*php", re.I | re.M)),
    ("header", "asp.net", re.compile(r"^x-aspnet", re.I | re.M)),
    ("cookie", "wordpress", re.compile(r"wp-content|wp-includes", re.I)),
    ("cookie", "drupal", re.compile(r"drupal", re.I)),
    ("cookie", "joomla", re.compile(r"joomla", re.I)),
    ("html", "react", re.compile(r"__NEXT_DATA__|react", re.I)),
    ("html", "vue", re.compile(r"data-vue|vue\.js", re.I)),
    ("html", "angular", re.compile(r"ng-app|angular", re.I)),
    ("html", "django", re.compile(r"csrfmiddlewaretoken", re.I)),
    ("html", "laravel", re.compile(r"laravel_session|csrf-token", re.I)),
    ("html", "squarespace", re.compile(r"squarespace", re.I)),
    ("html", "shopify", re.compile(r"cdn\.shopify\.com", re.I)),
    ("html", "wix", re.compile(r"static\.wixstatic\.com", re.I)),
    ("html", "google analytics", re.compile(r"google-analytics|gtag/js", re.I)),
    ("html", "cloudflare cdn", re.compile(r"cdn-cgi", re.I)),
]


class TechFingerprintModule:
    name = "fingerprint"

    def __init__(self, ctx: ScanContext, hosts: list[str] | None = None, timeout: float = 12.0) -> None:
        self.ctx = ctx
        self.hosts = hosts or [ctx.domain]
        self.timeout = timeout

    def run(self) -> None:
        client = build_client(timeout=self.timeout)
        try:
            with ThreadPoolExecutor(max_workers=10) as pool:
                futs = [pool.submit(self._fingerprint, client, f"https://{h}") for h in self.hosts]
                for fut in as_completed(futs):
                    try:
                        res = fut.result()
                    except Exception:
                        continue
                    for tech, evidence in (res or []):
                        self.ctx.add(Finding(self.name, "tech", tech, detail={"evidence": evidence}))
        finally:
            client.close()

    def _fingerprint(self, client, url: str) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        try:
            r = client.get(url)
        except Exception:
            return out
        body = "\n".join([str(r.headers), r.text[:40_000]])
        for kind, tech, pat in SIGNATURES:
            m = pat.search(body)
            if m:
                out.append((tech, f"{kind}:{m.group(0)[:80]}"))
        # interesting security headers
        for h in ["strict-transport-security", "content-security-policy", "x-frame-options",
                  "x-content-type-options"]:
            if h in {k.lower() for k in r.headers}:
                out.append((f"header:{h}", "present"))
            else:
                out.append((f"header:{h}", "MISSING"))
        return out
