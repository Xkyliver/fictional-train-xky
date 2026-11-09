#!/usr/bin/env python3
"""
APKMirror Helper: curl_cffi -> cloudscraper -> real-browser fallback
"""
import sys
import os
import re
import time
import argparse
import urllib.parse
import json
import hashlib
import tempfile
import fcntl
from bs4 import BeautifulSoup

try:
    from curl_cffi import requests as curl_requests  # TLS/JA3 impersonation
except ImportError:
    curl_requests = None
try:
    import cloudscraper
except ImportError:
    cloudscraper = None

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

# Used when APKMirror is unreachable, so the build at least gets a pkg name
KNOWN_PKGS = {
    "youtube": "com.google.android.youtube",
    "youtube-music": "com.google.android.apps.youtube.music",
    "reddit": "com.reddit.frontpage",
    "twitter": "com.twitter.android",
    "tiktok": "com.zhiliaoapp.musically",
}


CACHE_DIR = os.environ.get("APKMIRROR_CACHE_DIR") or os.path.join(tempfile.gettempdir(), "apkmirror_cache")
PAGE_TTL = 900     # seconds a cached HTML page stays valid
COOKIE_TTL = 3000  # seconds a cached cf_clearance is trusted
# Browser profiles tried in order when Cloudflare answers 403/503
IMPERSONATE = ["chrome", "safari", "firefox", "edge"]


class CachedResponse:
    status_code = 200

    def __init__(self, text):
        self.text = text
        self.content = text.encode("utf-8")


class Fetcher:
    """HTTP client that escalates when Cloudflare blocks us:
    curl_cffi (Chrome TLS fingerprint) -> cloudscraper -> real browser
    (SeleniumBase UC mode under xvfb) to get cf_clearance, whose cookies are
    then reused for fast requests. Set APKMIRROR_PROXY to route via a proxy.
    """

    def __init__(self):
        self.proxy = os.environ.get("APKMIRROR_PROXY") or None
        self.ua = UA
        self.cookies = {}
        self.browser_done = False
        self.imp_idx = 0       # index into IMPERSONATE
        self.had_success = False
        os.makedirs(CACHE_DIR, exist_ok=True)
        self._load_cookies()
        self._build_session()

    # ---- cross-process cookie cache: the browser solve only happens once ----
    def _cookie_file(self):
        return os.path.join(CACHE_DIR, "cf.json")

    def _load_cookies(self):
        try:
            with open(self._cookie_file()) as f:
                d = json.load(f)
            if time.time() - d["ts"] < COOKIE_TTL and d.get("cookies"):
                self.cookies, self.ua = d["cookies"], d["ua"]
                return True
        except Exception:
            pass
        return False

    def _save_cookies(self):
        try:
            with open(self._cookie_file(), "w") as f:
                json.dump({"ts": time.time(), "cookies": self.cookies, "ua": self.ua}, f)
        except Exception:
            pass

    # ---- short-lived page cache: same listing page is fetched by several calls ----
    def _page_file(self, url):
        return os.path.join(CACHE_DIR, hashlib.sha1(url.encode()).hexdigest() + ".html")

    def _page_get(self, url):
        fp = self._page_file(url)
        try:
            if time.time() - os.path.getmtime(fp) < PAGE_TTL:
                with open(fp, encoding="utf-8") as f:
                    return CachedResponse(f.read())
        except Exception:
            pass
        return None

    def _page_put(self, url, r):
        try:
            with open(self._page_file(url), "w", encoding="utf-8") as f:
                f.write(r.text)
        except Exception:
            pass

    def _build_session(self):
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
        if curl_requests:
            self.kind = "curl_cffi"
            self.session = None
            while self.imp_idx < len(IMPERSONATE):
                try:
                    self.session = curl_requests.Session(impersonate=IMPERSONATE[self.imp_idx], proxies=proxies)
                    break
                except Exception:   # profile unknown to this curl_cffi version
                    self.imp_idx += 1
            if self.session is None:
                raise RuntimeError("No usable curl_cffi impersonation profile")
        elif cloudscraper:
            self.kind = "cloudscraper"
            self.session = cloudscraper.create_scraper()
            if proxies:
                self.session.proxies.update(proxies)
        else:
            raise RuntimeError("Install curl_cffi (pip install curl_cffi) or cloudscraper")
        self.session.headers.update({"Accept-Language": "en-US,en;q=0.9"})
        # IMPORTANT: never override User-Agent for curl_cffi unless we hold browser
        # cookies. A hard-coded UA that disagrees with the impersonated TLS/HTTP2
        # fingerprint is exactly what makes Cloudflare answer 403.
        # cf_clearance, however, is bound to the UA of the browser that solved it.
        if self.cookies:
            self.session.headers.update({"User-Agent": self.ua})
        elif self.kind == "cloudscraper":
            self.session.headers.update({"User-Agent": self.ua})
        for k, v in self.cookies.items():
            self.session.cookies.set(k, v, domain=".apkmirror.com")

    def _rotate_profile(self):
        """Switch to the next TLS fingerprint. Only while nothing has worked yet."""
        if self.kind != "curl_cffi" or self.had_success or self.cookies:
            return False
        if self.imp_idx + 1 >= len(IMPERSONATE):
            return False
        self.imp_idx += 1
        print(f"Blocked, retrying as '{IMPERSONATE[self.imp_idx]}'", file=sys.stderr)
        self._build_session()
        return True

    @staticmethod
    def _norm(url):
        # APKMirror directory pages are canonical with a trailing slash
        u = urllib.parse.urlsplit(url)
        if u.netloc.endswith("apkmirror.com") and not u.query and not u.path.endswith("/") \
                and "." not in u.path.rsplit("/", 1)[-1]:
            return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path + "/", "", ""))
        return url

    def _solve_with_browser(self, url):
        if self.browser_done:
            return False
        self.browser_done = True
        # serialize across parallel processes; if another one already solved, reuse it
        lock = open(os.path.join(CACHE_DIR, "solve.lock"), "w")
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            old = dict(self.cookies)
            if self._load_cookies() and self.cookies != old:
                self._build_session()
                return True
            return self._do_solve(url)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()

    def _do_solve(self, url):
        try:
            from seleniumbase import SB
        except ImportError:
            print("seleniumbase not installed, cannot solve Cloudflare challenge "
                  "(pip install seleniumbase)", file=sys.stderr)
            return False
        print("Blocked by Cloudflare, solving with a real browser...", file=sys.stderr)
        try:
            kw = dict(uc=True, test=True, headless=False, xvfb=True, locale_code="en")
            if self.proxy:
                kw["proxy"] = self.proxy.replace("http://", "").replace("https://", "")
            with SB(**kw) as sb:
                sb.uc_open_with_reconnect(url, reconnect_time=3)
                for _ in range(4):
                    if "just a moment" not in sb.get_title().lower():
                        break
                    try:
                        sb.uc_gui_click_captcha()
                    except Exception:
                        pass
                    sb.sleep(2)
                self.ua = sb.execute_script("return navigator.userAgent")
                self.cookies = {c["name"]: c["value"] for c in sb.driver.get_cookies()}
            ok = "cf_clearance" in self.cookies
            print(f"Browser solve {'succeeded' if ok else 'did not get cf_clearance'}", file=sys.stderr)
            if ok:
                self._save_cookies()
            self._build_session()
            return ok
        except Exception as e:
            print(f"Browser solve failed: {e}", file=sys.stderr)
            return False

    def get(self, url, headers=None, stream=False):
        url = self._norm(url)
        if not stream:
            cached = self._page_get(url)
            if cached:
                return cached
        do = lambda: self.session.get(url, headers=headers or {}, stream=stream, timeout=60)
        r = do()
        while r.status_code in (403, 503) and self._rotate_profile():
            r = do()
        if r.status_code in (403, 503) and self._solve_with_browser(url):
            r = do()
        if r.status_code == 200:
            self.had_success = True
            if not stream:
                self._page_put(url, r)
        return r


def get_scraper():
    return Fetcher()


def safe_get(scraper, url: str, referer: str = None, max_retries: int = 3):
    headers = {}
    if referer:
        headers["Referer"] = referer
    for attempt in range(max_retries):
        try:
            r = scraper.get(url, headers=headers)
            if r.status_code == 200:
                return r
            elif r.status_code in (429, 503, 504):
                wait = (attempt + 1) * 3
                print(f"Request to {url} returned {r.status_code}, waiting {wait}s...", file=sys.stderr)
                time.sleep(wait)
            else:
                print(f"Request to {url} returned status {r.status_code}", file=sys.stderr)
                return r
        except Exception as e:
            print(f"Request to {url} failed with exception: {e}", file=sys.stderr)
            time.sleep(2)
    return None

def sanitize_version(version: str) -> str:
    return re.sub(r'[^a-zA-Z0-9]+', '-', version).strip('-').lower()

def compact_version(version: str) -> str:
    return re.sub(r'[^a-zA-Z0-9]', '', version).lower()

def get_pkg_name(scraper, base_url: str) -> str:
    try:
        r = safe_get(scraper, base_url)
        if r and r.status_code == 200:
            soup = BeautifulSoup(r.content, "html.parser")
            link = soup.find("a", href=re.compile(r"details\?id=([a-zA-Z0-9_\.]+)"))
            if link and "href" in link.attrs:
                m = re.search(r"details\?id=([a-zA-Z0-9_\.]+)", link["href"])
                if m:
                    return m.group(1)
            for a in soup.find_all("a", href=True):
                if "id=" in a["href"]:
                    m = re.search(r"id=([a-zA-Z0-9_\.]+)", a["href"])
                    if m:
                        return m.group(1)
    except Exception:
        pass
    slug = base_url.rstrip("/").split("/")[-1].lower()
    return KNOWN_PKGS.get(slug, "")

def get_versions_list(scraper, base_url: str) -> list[str]:
    r = safe_get(scraper, base_url)
    if not r or r.status_code != 200:
        raise Exception(f"Failed to fetch {base_url}")
    soup = BeautifulSoup(r.content, "html.parser")
    container = soup.find(id="primary") or soup
    versions = []
    for a in container.find_all("a", {"class": "fontBlack"}):
        text = a.get_text(strip=True)
        if "wear os" in text.lower() or "android tv" in text.lower():
            continue
        m = re.search(r'(\d+(\.\d+)+[a-zA-Z0-9_\-]*)', text)
        if m:
            v = m.group(1).strip()
            if v and "beta" not in v.lower() and "alpha" not in v.lower() and v not in versions:
                versions.append(v)
    if not versions:
        for span in container.find_all("span", {"class": "infoSlide-value"}):
            text = span.get_text(strip=True)
            if re.match(r'^\d+(\.\d+)+([a-zA-Z0-9_\-]+)?$', text):
                if "beta" not in text.lower() and "alpha" not in text.lower() and text not in versions:
                    versions.append(text)
    return versions

def is_version_match(href: str, v_slug: str, v_compact: str) -> bool:
    href_l = href.lower()
    if "#" in href_l:
        return False
    if not (href_l.startswith("/apk/") or "apkmirror.com/apk/" in href_l):
        return False
    if any(x in href_l for x in ("apk-download", "variant-", "download.php", "/author/", "/apk/page/")):
        return False
    if v_slug in href_l:
        return True
    href_compact = re.sub(r'[^a-zA-Z0-9]', '', href_l)
    if v_compact and len(v_compact) >= 4 and v_compact in href_compact:
        return True
    return False

def page_has_variants(html_text: str) -> bool:
    if not html_text:
        return False
    soup = BeautifulSoup(html_text, "html.parser")
    if soup.find("a", href=re.compile(r"-apk-download/?$")):
        return True
    table = soup.find("div", {"class": ["variants-table", "table"]})
    if table and table.find("a", href=re.compile(r"-apk-download/?$")):
        return True
    dl_btn = soup.find("a", {"class": re.compile(r"downloadButton")})
    if dl_btn and dl_btn.get("href") and not dl_btn["href"].startswith("#"):
        return True
    return False

def find_version_page(scraper, base_url: str, version: str):
    app_slug = base_url.rstrip('/').split('/')[-1]
    v_slug = sanitize_version(version)
    v_compact = compact_version(version)

    v_parts = version.split('.')
    v_trim = '.'.join(v_parts[:3]) if len(v_parts) > 3 else None
    v_trim_slug = sanitize_version(v_trim) if v_trim else None
    v_trim_compact = compact_version(v_trim) if v_trim else None
    
    title_slug = None
    # 1. Base listing page (most reliable & avoids guessing)
    r = safe_get(scraper, base_url)
    if r and r.status_code == 200:
        soup = BeautifulSoup(r.content, "html.parser")
        h1 = soup.find("h1", {"class": "marginZero"})
        if h1:
            title_slug = sanitize_version(h1.get_text(strip=True))

        matching_links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if is_version_match(href, v_slug, v_compact) or (v_trim_slug and is_version_match(href, v_trim_slug, v_trim_compact)):
                matching_links.append(href)
        
        # Sort candidates: prefer those containing '-release' and matching exact slug
        matching_links.sort(key=lambda h: (1 if "-release" in h.lower() else 0, 1 if v_slug in h.lower() else 0), reverse=True)
        
        for href in matching_links[:5]:
            full_url = "https://www.apkmirror.com" + href if href.startswith("/") else href
            r2 = safe_get(scraper, full_url, referer=base_url)
            if r2 and r2.status_code == 200 and page_has_variants(r2.text):
                return full_url, r2

    # 2. Try candidate URLs: PRIORITIZE -release candidates
    candidates = []
    if title_slug:
        candidates.append(f"{base_url.rstrip('/')}/{title_slug}-{v_slug}-release/")
        if v_trim_slug:
            candidates.append(f"{base_url.rstrip('/')}/{title_slug}-{v_trim_slug}-release/")
    candidates.append(f"{base_url.rstrip('/')}/{app_slug}-{v_slug}-release/")
    if v_trim_slug:
        candidates.append(f"{base_url.rstrip('/')}/{app_slug}-{v_trim_slug}-release/")
    candidates.append(f"{base_url.rstrip('/')}/{v_slug}-release/")
    if v_trim_slug:
        candidates.append(f"{base_url.rstrip('/')}/{v_trim_slug}-release/")
    
    # Non -release fallbacks
    if title_slug:
        candidates.append(f"{base_url.rstrip('/')}/{title_slug}-{v_slug}/")
        if v_trim_slug:
            candidates.append(f"{base_url.rstrip('/')}/{title_slug}-{v_trim_slug}/")
    candidates.append(f"{base_url.rstrip('/')}/{app_slug}-{v_slug}/")
    if v_trim_slug:
        candidates.append(f"{base_url.rstrip('/')}/{app_slug}-{v_trim_slug}/")
    candidates.append(f"{base_url.rstrip('/')}/{v_slug}/")
    if v_trim_slug:
        candidates.append(f"{base_url.rstrip('/')}/{v_trim_slug}/")

    for url in candidates:
        r2 = safe_get(scraper, url, referer=base_url)
        if r2 and r2.status_code == 200 and page_has_variants(r2.text):
            return url, r2

    # 3. Search APKMirror fallback
    search_q = f"{app_slug.replace('-', ' ')} {v_trim if v_trim else version}"
    search_url = f"https://www.apkmirror.com/?post_type=app_release&searchtype=apk&s={urllib.parse.quote(search_q)}"
    print(f"Searching APKMirror: {search_url}", file=sys.stderr)
    r_search = safe_get(scraper, search_url, referer=base_url)
    if r_search and r_search.status_code == 200:
        soup = BeautifulSoup(r_search.content, "html.parser")
        matching_search = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if is_version_match(href, v_slug, v_compact) or (v_trim_slug and is_version_match(href, v_trim_slug, v_trim_compact)):
                matching_search.append(href)
        matching_search.sort(key=lambda h: (1 if "-release" in h.lower() else 0, 1 if v_slug in h.lower() else 0), reverse=True)
        for href in matching_search[:3]:
            full_url = "https://www.apkmirror.com" + href if href.startswith("/") else href
            r2 = safe_get(scraper, full_url, referer=search_url)
            if r2 and r2.status_code == 200 and page_has_variants(r2.text):
                return full_url, r2

    raise Exception(f"Could not find APKMirror page for version '{version}' at {base_url}")

def download_file(scraper, direct_url: str, referer: str, out_path: str):
    dir_name = os.path.dirname(out_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    headers = {"Referer": referer}
    print(f"Downloading from {direct_url} -> {out_path}", file=sys.stderr)
    r = scraper.get(direct_url, stream=True, headers=headers)
    try:
        r.raise_for_status()
        with open(out_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=1 << 20):
                if chunk:
                    f.write(chunk)
    finally:
        r.close()
    print(f"Downloaded successfully: {out_path} ({os.path.getsize(out_path)} bytes)", file=sys.stderr)

def parse_size_bytes(soup):
    """File size (bytes) shown on a variant / download page, or None."""
    text = soup.get_text(" ", strip=True)
    m = re.search(r"([\d,]{5,})\s*bytes", text, re.I)
    if m:
        return int(m.group(1).replace(",", ""))
    m = re.search(r"(?:file\s*size|size)\s*:?\s*([\d.,]+)\s*([KMG])i?B", text, re.I)
    if m:
        return int(float(m.group(1).replace(",", "")) * 1024 ** ("KMG".index(m.group(2).upper()) + 1))
    return None

def resolve_variant(scraper, v, version_url):
    """Walk variant page -> download page -> direct link. Fills dl_page, direct, size."""
    r_variant = safe_get(scraper, v["url"], referer=version_url)
    if not r_variant or r_variant.status_code != 200:
        raise Exception(f"variant page returned {getattr(r_variant, 'status_code', None)}")
    soup_var = BeautifulSoup(r_variant.content, "html.parser")
    v["size"] = parse_size_bytes(soup_var)
    dl_btn = soup_var.find("a", {"class": re.compile(r"downloadButton")})
    if not dl_btn or not dl_btn.get("href"):
        raise Exception("download button not found")
    href = dl_btn["href"].strip()
    v["dl_page"] = "https://www.apkmirror.com" + href if href.startswith("/") else href

    r_dl = safe_get(scraper, v["dl_page"], referer=v["url"])
    if not r_dl or r_dl.status_code != 200:
        raise Exception(f"download page returned {getattr(r_dl, 'status_code', None)}")
    soup_dl = BeautifulSoup(r_dl.content, "html.parser")
    if v["size"] is None:
        v["size"] = parse_size_bytes(soup_dl)
    link = (soup_dl.find("a", href=re.compile(r"download\.php"))
            or soup_dl.find("a", {"rel": "nofollow", "href": re.compile(r"download\.php|/wp-content/")})
            or soup_dl.find("a", string=re.compile(r"here", re.I))
            or soup_dl.find("a", {"rel": "nofollow"}))
    if not link or not link.get("href"):
        raise Exception("direct link not found")
    href = link["href"].strip()
    v["direct"] = "https://www.apkmirror.com" + href if href.startswith("/") else href

def probe_content_length(scraper, v):
    """Last resort: ask the file server for the size without downloading the body."""
    try:
        r = scraper.get(v["direct"], stream=True, headers={"Referer": v["dl_page"]})
        try:
            if r.status_code == 200:
                cl = r.headers.get("content-length")
                return int(cl) if cl and cl.isdigit() else None
        finally:
            r.close()
    except Exception:
        pass
    return None

def download_apkmirror(base_url: str, version: str, output: str, arch: str = "all", dpi: str = ""):
    scraper = get_scraper()
    
    version_url, resp = find_version_page(scraper, base_url, version)
    print(f"Found version page: {version_url}", file=sys.stderr)
    
    soup = BeautifulSoup(resp.content, "html.parser")
    raw_variants = []
    
    table = soup.find("div", {"class": ["table", "variants-table"]})
    if not table:
        table = soup.find("div", {"class": re.compile(r"variants-table")})
    
    if table:
        rows = table.find_all("div", {"class": re.compile(r"table-row")})
        if not rows:
            rows = table.find_all("div", recursive=False)[1:]
        for row in rows:
            cells = row.find_all("div", {"class": "table-cell"}, recursive=False)
            if not cells:
                continue
            
            link_el = row.find("a", href=re.compile(r"-apk-download/?$")) or row.find("a", {"class": "accent_color"})
            if not link_el or not link_el.get("href"):
                continue
            
            href = link_el["href"].strip()
            if href.startswith("#") or "all_versions" in href or "variant-" in href:
                continue
            
            badge = row.find("span", {"class": re.compile(r"apkm-badge")})
            badge_text = badge.text.strip().upper() if badge else ""
            is_bundle = ("BUNDLE" in badge_text) or ("bundle" in href.lower())
            
            variant_arch = "universal"
            for c in cells:
                c_text = c.get_text(strip=True).lower()
                if any(a in c_text for a in ("arm64-v8a", "armeabi-v7a", "arm", "x86_64", "x86", "universal", "noarch")):
                    variant_arch = c_text
                    break
            
            variant_dpi = " ".join(c.get_text(strip=True).lower() for c in cells
                                   if "dpi" in c.get_text(strip=True).lower())
            variant_url = "https://www.apkmirror.com" + href if href.startswith("/") else href
            raw_variants.append({
                "is_bundle": is_bundle,
                "url": variant_url,
                "arch": variant_arch,
                "dpi": variant_dpi
            })
    
    # Fallback: check all -apk-download links directly on page
    if not raw_variants:
        for a in soup.find_all("a", href=re.compile(r"-apk-download/?$")):
            href = a["href"].strip()
            if href and not href.startswith("#") and "variant-" not in href:
                variant_url = "https://www.apkmirror.com" + href if href.startswith("/") else href
                raw_variants.append({
                    "is_bundle": "bundle" in href.lower(),
                    "url": variant_url,
                    "arch": "universal",
                    "dpi": ""
                })
    
    # If no variants in table, check if page itself has downloadButton
    if not raw_variants:
        dl_btn = soup.find("a", {"class": re.compile(r"downloadButton")})
        if dl_btn and dl_btn.get("href"):
            href = dl_btn["href"].strip()
            if href and not href.startswith("#"):
                variant_url = "https://www.apkmirror.com" + href if href.startswith("/") else href
                raw_variants.append({
                    "is_bundle": False,
                    "url": variant_url,
                    "arch": "universal",
                    "dpi": ""
                })
    
    if not raw_variants:
        raise Exception(f"No variants found for {version}")
    
    # ---- variant selection: target arch only (e.g. arm64-v8a), SMALLEST size wins ----
    target_arch = arch.lower() if arch else "all"
    v_parts = version.split('.')
    sub_ver = v_parts[-1] if len(v_parts) > 3 else ""
    dpi_l = (dpi or "").lower()

    if target_arch in ("all", "both"):
        pool = list(raw_variants)
    else:
        pool = [v for v in raw_variants if target_arch in v["arch"]]
        if not pool:  # no exact-arch build at all: accept universal ones
            pool = [v for v in raw_variants if "universal" in v["arch"] or "noarch" in v["arch"]]
        pool = pool or list(raw_variants)
    if sub_ver:  # exact build requested (4-part version)
        pool = [v for v in pool if sub_ver in v["url"]] or pool
    if dpi_l and dpi_l != "nodpi":
        pool = [v for v in pool if dpi_l in v["dpi"]] or pool

    last_err = None
    for v in pool:  # resolve links + sizes (pages are cached, so this is cheap)
        v["size"], v["failed"] = None, False
        try:
            resolve_variant(scraper, v, version_url)
            if v["size"] is None and len(pool) > 1:
                v["size"] = probe_content_length(scraper, v)
        except Exception as e:
            v["failed"], last_err = True, e
        print(f"  candidate: arch={v['arch']} bundle={v['is_bundle']} "
              f"size={v['size'] if v['size'] is not None else '?'}"
              f"{' (unresolvable: ' + str(last_err) + ')' if v['failed'] else ''} {v['url']}", file=sys.stderr)

    ok = [v for v in pool if not v["failed"]]
    # smallest first (apk or apkm, no preference); unknown sizes last
    ok.sort(key=lambda v: (v["size"] is None, v["size"] or 0))
    if len(ok) > 1 and ok[0]["size"] is None:
        print("  WARNING: could not determine any variant size, using page order", file=sys.stderr)

    for idx, selected in enumerate(ok):
        size_txt = f"{selected['size'] / 1048576:.1f} MiB" if selected["size"] else "unknown size"
        print(f"Selected variant {idx+1}/{len(ok)} ({size_txt}, bundle={selected['is_bundle']}, "
              f"arch={selected['arch']}): {selected['url']}", file=sys.stderr)
        try:
            actual_output = output
            if selected["is_bundle"] and not actual_output.endswith(".apkm"):
                actual_output = f"{output}.apkm"
            download_file(scraper, selected["direct"], selected["dl_page"], actual_output)
            print(actual_output)
            return actual_output
        except Exception as e:
            last_err = e
            print(f"  Download failed: {e}", file=sys.stderr)

    raise Exception(f"All variants failed for {version}. Last error: {last_err}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="APKMirror Helper")
    parser.add_argument("url", nargs="?", help="APKMirror app URL")
    parser.add_argument("version", nargs="?", help="App version")
    parser.add_argument("output", nargs="?", help="Output file path")
    parser.add_argument("arch", nargs="?", default="all", help="Target architecture")
    parser.add_argument("dpi", nargs="?", default="", help="Target DPI")
    parser.add_argument("--pkg-name", dest="pkg_url", help="Get package name for URL")
    parser.add_argument("--versions", dest="versions_url", help="Get version list for URL")
    
    args = parser.parse_args()
    scraper = get_scraper()
    
    if args.pkg_url:
        print(get_pkg_name(scraper, args.pkg_url))
        sys.exit(0)
    elif args.versions_url:
        for v in get_versions_list(scraper, args.versions_url):
            print(v)
        sys.exit(0)
        
    if not args.url or not args.version or not args.output:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    try:
        download_apkmirror(args.url, args.version, args.output, args.arch, args.dpi)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
