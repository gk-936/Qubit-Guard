"""
Mobile application scanner service.
Real store metadata + TLS probing of app backend APIs.
"""

import json
import re
import ssl
import socket
import logging
import urllib.request
import urllib.error
from urllib.parse import urlparse
from datetime import datetime

log = logging.getLogger(__name__)

# Fallback anchor for when the App Store lists a real, confirmed developer name
# (sellerName) but no sellerUrl — this happens for real bank apps, not just
# obscure ones (Punjab National Bank's own "PNB ONE" app has no sellerUrl).
# Deliberately small and limited to the banks this tool is built to audit,
# with domains already verified reachable elsewhere in this codebase this
# session — not a general-purpose registry, and not a guess.
KNOWN_BANK_DOMAINS = {
    "punjab national bank": "pnbindia.in",
    "state bank of india": "sbi.co.in",
    "hdfc bank": "hdfcbank.com",
    "icici bank": "icicibank.com",
    "axis bank": "axisbank.com",
    "kotak mahindra bank": "kotak.com",
    "bank of india": "bankofindia.co.in",
    "bank of baroda": "bankofbaroda.in",
    "yes bank": "yesbank.in",
}


def search_mobile_apps(query: str = "") -> list:
    """Search for real mobile applications via the iTunes Search API and filter for verified banking apps."""
    if not query:
        return []

    results = []
    
    # Apple iTunes Search API — reliable public API for discovering mobile apps.
    # Restricted to the Indian App Store storefront: every bank this tool audits
    # is Indian, but common abbreviations like "PNB" collide with completely
    # unrelated banks worldwide (Philippine National Bank, several different US
    # "Peoples National Bank"s, Pike National Bank...). Confirmed live: searching
    # "PNB" without a country filter returned 10 apps, only 3 of which were
    # actually Punjab National Bank's. Restricting to country=IN cut that down to
    # 1 false positive out of 15 (and surfaced real PNB apps the unfiltered
    # search had missed, e.g. BHIM PNB, PNB Digital Rupee). It doesn't fully
    # eliminate cross-region false positives on its own — see the developer-name
    # field returned below, which is the stronger signal for telling them apart.
    try:
        search_query = urllib.parse.quote(query)
        url = f"https://itunes.apple.com/search?term={search_query}&entity=software&limit=20&country=IN"
        req = urllib.request.Request(url, headers={"User-Agent": "QuantumShield-Discovery/2.0"})
        
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            for item in data.get("results", []):
                app_name = item.get("trackName", "")
                bundle_id = item.get("bundleId", "")
                developer = item.get("artistName", "Unknown")

                # iTunes' search does its own fuzzy/related matching internally and
                # will return apps with no textual connection to the query at all —
                # confirmed live: searching "PNB" returned Gmail, PhonePe, Airtel,
                # among others, none of which mention "PNB" anywhere. Apple doesn't
                # explain why (probably genre/popularity backfill on a short query),
                # so rather than trying to out-guess it, drop anything that doesn't
                # actually contain the search term in name, bundle ID, OR developer.
                # This applies to any query, not just PNB.
                name_match = query.lower() in app_name.lower() or query.lower() in bundle_id.lower()
                dev_match = query.lower() in developer.lower()
                if not (name_match or dev_match):
                    continue

                # Heuristic classification, not a verified developer identity check —
                # there is no whitelist of each bank's actual developer IDs to match
                # against. "Official" only means the search term appears in the
                # name/bundle ID; "Verified" means only the developer name matched.
                status = "Official" if name_match else "Verified"
                status_basis = (
                    f'App name or bundle ID contains the search term "{query}".'
                    if name_match else
                    f'Developer name ("{developer}") contains the search term "{query}", '
                    f'but the app name/bundle ID did not — not confirmed as an official listing.'
                )

                # userRatingCount distinguishes "no ratings yet" from "rated 0/5" —
                # both otherwise report averageUserRating as 0, which is misleading.
                rating_count = item.get("userRatingCount", 0)
                rating = item.get("averageUserRating") if rating_count > 0 else None

                results.append({
                    "id": bundle_id,
                    "name": app_name,
                    "platform": "iOS",
                    "status": status,
                    "status_basis": status_basis,
                    "rating": rating,
                    "rating_count": rating_count,
                    "developer": developer,
                    "source": "itunes-search",
                })
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        log.debug("iTunes search failed for %r: %s", query, e)

    # Android: There is no free official Play Store search API, so real Android
    # discovery is not available here. Rather than fabricate independent Android
    # results, we derive a *labelled guess* from each verified iOS listing (most
    # banks reuse the same reverse-domain package ID across platforms) and mark it
    # explicitly so no consumer can mistake it for an independently verified finding.
    android_results = []
    for app in results:
        android_results.append({
            "id": app["id"],
            "name": app["name"],
            "platform": "Android",
            "status": app["status"],
            "status_basis": app["status_basis"],
            "rating": app["rating"],
            "rating_count": app["rating_count"],
            "developer": app["developer"],
            "source": "derived-from-ios",
            "note": "Android listing inferred from the verified iOS App Store entry; not independently confirmed via Play Store.",
        })

    return sorted(results + android_results, key=lambda x: x["status"] != "Official")


def _fetch_store_metadata(app_id: str, platform: str) -> dict:
    """Fetch real app metadata from store APIs."""
    metadata = {"version": "Unknown", "name": None, "size": "N/A", "seller_domain": None, "seller_domain_basis": None, "seller_name": None}

    # Look up the iTunes entry for this bundle ID regardless of platform. Android
    # entries in this tool always reuse the exact same bundle ID as their iOS
    # counterpart (see search_mobile_apps' "derived-from-ios" entries) — the real
    # company behind the app doesn't change with the platform, so the same
    # sellerUrl/sellerName-based domain discovery applies to both. Previously this
    # only ran for platform == "iOS", so scanning the *Android* row for an app that
    # needed the sellerName fallback (e.g. PNB ONE) fell straight back to the
    # unreliable bundle-ID guess even though the iOS scan of the identical app ID
    # already had a confirmed answer.
    try:
        url = f"https://itunes.apple.com/lookup?bundleId={app_id}"
        req = urllib.request.Request(url, headers={"User-Agent": "QuantumShield-Scanner/2.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            if data.get("resultCount", 0) > 0:
                result = data["results"][0]
                if platform == "iOS":
                    metadata["version"] = result.get("version", "Unknown")
                    metadata["name"] = result.get("trackName")
                    size_bytes = result.get("fileSizeBytes", 0)
                    if size_bytes:
                        metadata["size"] = f"{int(size_bytes) / (1024*1024):.1f} MB"
                # The developer's own listed website — a real, App Store-confirmed
                # anchor, and a far better basis for the API-domain probe below
                # than guessing "www.{bundle-id-segment}.com". Different apps with
                # different bundle IDs that happen to derive the same guessed
                # domain were previously returning identical results even when
                # they're unrelated apps (e.g. a white-label vendor's own site).
                seller_url = result.get("sellerUrl")
                if seller_url:
                    try:
                        host = urlparse(seller_url).hostname
                        if host:
                            metadata["seller_domain"] = host
                            metadata["seller_domain_basis"] = "confirmed — App Store developer URL"
                    except ValueError:
                        pass

                # sellerUrl is often simply absent even for real, well-known banks
                # (confirmed: Punjab National Bank's own "PNB ONE" app has none).
                # sellerName is still real, Apple-confirmed data — check it against
                # the small curated list above before giving up to a bundle-ID guess.
                metadata["seller_name"] = result.get("sellerName")
                if not metadata["seller_domain"]:
                    seller_name = (result.get("sellerName") or "").strip().lower()
                    for bank_name, domain in KNOWN_BANK_DOMAINS.items():
                        if bank_name in seller_name:
                            metadata["seller_domain"] = domain
                            metadata["seller_domain_basis"] = f'confirmed — App Store developer name matched "{bank_name.title()}"'
                            break
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        log.debug("iTunes lookup failed for %s: %s", app_id, e)

    if platform != "iOS":
        # Android: Play Store page for a more accurate Android version/size —
        # the iTunes lookup above already covered seller_domain discovery.
        try:
            url = f"https://play.google.com/store/apps/details?id={app_id}&hl=en"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept-Language": "en-US,en;q=0.9",
            })
            with urllib.request.urlopen(req, timeout=5) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
                # Try multiple patterns to extract version
                for pattern in [
                    r'\[\[\["(\d+\.\d+[\.\d]*)"',
                    r'softwareVersion["\s:]+["\']?(\d+\.\d+[\.\d]*)',
                    r'Current Version.*?(\d+\.\d+[\.\d]*)',
                ]:
                    ver_match = re.search(pattern, html)
                    if ver_match:
                        metadata["version"] = ver_match.group(1)
                        break
        except (urllib.error.URLError, OSError) as e:
            log.debug("Android store metadata fetch failed for %s: %s", app_id, e)

    return metadata


def _guess_domains_from_seller_name(seller_name: str) -> list:
    """Build domain candidates from the App Store's confirmed developer name.

    Generic — not limited to the banks in KNOWN_BANK_DOMAINS — so a bank
    outside that curated list still gets a real shot at resolving to its
    actual domain, instead of falling straight to guessing off the bundle ID
    (an app's package identifier is an arbitrary developer choice; the
    App-Store-listed company name is real, confirmed data and a better basis
    to guess from, even though it's still ultimately a guess, not confirmed).
    """
    if not seller_name:
        return []

    stopwords = {"the", "of", "and", "ltd", "limited", "pvt", "private", "co", "inc", "corp", "corporation"}
    words = [w for w in re.split(r"[^a-zA-Z]+", seller_name) if w]
    significant = [w for w in words if w.lower() not in stopwords]
    if not significant:
        return []

    # Try the company's own first significant word FIRST — many Indian banks
    # (HDFC, ICICI, SBI...) are already known by a short brand-name/initialism
    # that IS the word itself, not a further abbreviation of "{Word} Bank Ltd".
    # An acronym-of-an-acronym here is actively dangerous: "HDFC Bank Ltd" would
    # otherwise abbreviate to "hbl", which happens to be a real, unrelated bank
    # (Habib Bank Limited) — a coincidental collision, not a fabricated result,
    # but one worth avoiding by trying the safer guess first.
    first_word = significant[0].lower()

    # Second: a real acronym built from all significant words (stopwords like
    # "Bank"/"Ltd" excluded) — this is what "Punjab National Bank" -> "pnb"
    # needs, since neither significant word alone gets there.
    acronym = "".join(w[0] for w in significant).lower()

    guesses = []
    for base in dict.fromkeys([first_word, acronym]):  # dedupe, keep order
        if len(base) < 2:
            continue
        guesses.extend([
            f"{base}.com", f"www.{base}.com",
            f"{base}.in", f"www.{base}.in",
            f"{base}bank.com", f"www.{base}bank.com",
            f"{base}india.in", f"www.{base}india.in",
            f"{base}.co.in", f"www.{base}.co.in",
        ])
    return guesses


def _probe_app_api_tls(app_id: str, known_domain: str = None, known_domain_basis: str = None, seller_name: str = None) -> dict:
    """Probe the app's likely API domain for TLS posture.

    `known_domain` (from the App Store's own metadata — either the developer's
    listed website, or a curated bank-name match) is tried first when
    available — it's a confirmed anchor, not a guess. Falling straight to
    guessing "www.{bundle-id-segment}.com" was producing two kinds of wrong
    result: unrelated apps whose bundle IDs happen to share a second segment
    collapsed onto the identical guessed domain and returned identical
    findings, and white-label apps (built by a vendor for many banks) got
    assessed against the *vendor's* corporate site instead of the bank's,
    since the vendor's name is what's in the bundle ID.
    """
    candidates = []
    domain_evidence = {}

    if known_domain:
        candidates.append(known_domain)
        domain_evidence[known_domain] = known_domain_basis or "confirmed"

    # Second tier: guess from the confirmed developer name (works for any bank,
    # not just the ones in KNOWN_BANK_DOMAINS) — tried before the weaker
    # bundle-ID guess below, since the developer name is real, confirmed data.
    for guess in _guess_domains_from_seller_name(seller_name):
        if guess not in domain_evidence:
            candidates.append(guess)
            domain_evidence[guess] = f'guessed from the App Store developer name ("{seller_name}"), not confirmed'

    parts = app_id.split(".")
    if len(parts) >= 2 and parts[0] in ["com", "in", "org", "net"]:
        org = parts[1]  # e.g., "pnb"
        for guess in [
            f"api.{org}.com", f"www.{org}.com", f"{org}.com",
            f"api.{org}.co.in", f"www.{org}.co.in", f"{org}.co.in",
        ]:
            if guess not in domain_evidence:
                candidates.append(guess)
                domain_evidence[guess] = "guessed from the app's bundle ID, not confirmed"

    api_domain = None
    for candidate in candidates:
        try:
            socket.gethostbyname(candidate)
            api_domain = candidate
            break
        except socket.gaierror:
            continue

    if not api_domain:
        return {"reachable": False}

    try:
        context = ssl.create_default_context()
        with socket.create_connection((api_domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=api_domain) as tls_sock:
                cipher = tls_sock.cipher()
                tls_version = tls_sock.version()
                return {
                    "reachable": True,
                    "domain": api_domain,
                    "domain_basis": domain_evidence[api_domain],
                    "cipher_name": cipher[0] if cipher else "Unknown",
                    "cipher_bits": cipher[2] if cipher else 0,
                    "tls_version": tls_version,
                }
    except (OSError, ssl.SSLError, ValueError) as e:
        log.debug("API TLS probe failed for %s: %s", api_domain, e)
        return {"reachable": False, "domain": api_domain, "domain_basis": domain_evidence.get(api_domain)}


def scan_mobile_app(app_id: str, platform: str) -> dict:
    """
    Mobile app analysis combining real store metadata and TLS probing.
    """
    # 1. Fetch real store metadata
    store_meta = _fetch_store_metadata(app_id, platform)

    results = {
        "appId": app_id,
        "platform": platform,
        "version": store_meta["version"],
        "packageSize": store_meta["size"],
        "timestamp": datetime.utcnow().isoformat(),
        "findings": [],
        "pqc_score": None,  # None means "not assessed" until a probe succeeds or fails cleanly
    }

    # 2. Probe the app's API domain for TLS posture. Prefer a confirmed anchor
    # (developer's listed website, or a curated bank-name match), then a
    # developer-name-derived guess (works for any bank), then a bundle-ID guess.
    api_tls = _probe_app_api_tls(
        app_id,
        known_domain=store_meta.get("seller_domain"),
        known_domain_basis=store_meta.get("seller_domain_basis"),
        seller_name=store_meta.get("seller_name"),
    )

    if api_tls.get("reachable"):
        cipher_name = api_tls["cipher_name"]
        tls_version = api_tls["tls_version"]
        domain_note = f" [{api_tls.get('domain_basis')}]" if api_tls.get("domain_basis") else ""

        pqc_detected = any(m in cipher_name.upper() for m in ["KYBER", "MLKEM", "ML-KEM", "DILITHIUM", "ML-DSA"])

        if pqc_detected:
            results["findings"].append({
                "severity": "info",
                "issue": f"PQC-Ready API Backend: {cipher_name}",
                "detail": f"App's probed domain ({api_tls['domain']}{domain_note}) negotiated PQC-hybrid cipher: {cipher_name}.",
                "recommendation": None,
            })
            results["pqc_score"] = 0
            results["quantumSafe"] = True
        else:
            is_rsa = "RSA" in cipher_name and "ECDHE" not in cipher_name
            results["findings"].append({
                "severity": "critical" if is_rsa else "high",
                "issue": f"Classical Crypto on App Backend: {cipher_name}",
                "detail": f"App's probed domain ({api_tls['domain']}{domain_note}) uses {cipher_name} ({api_tls['cipher_bits']}-bit, {tls_version}). No PQC algorithms detected.",
                "recommendation": "Integrate liboqs or Bouncy Castle PQC providers. Enable hybrid X25519MLKEM768 on the API gateway.",
            })
            results["pqc_score"] = 100 if is_rsa else 85
            results["quantumSafe"] = False

            if tls_version and tls_version < "TLSv1.3":
                results["findings"].append({
                    "severity": "high",
                    "issue": f"Legacy TLS on App Backend: {tls_version}",
                    "detail": f"API domain {api_tls['domain']} uses {tls_version}. TLS 1.3 is required for PQC cipher suites.",
                    "recommendation": "Upgrade API gateway to TLS 1.3.",
                })
    else:
        # The app's backend could not be reached. Report that and nothing else — no
        # cryptographic claim (algorithm, severity, or score) is made about a host we
        # never reached. This mirrors the same fix applied to the web pillar in
        # scanner_engine.py: an unreachable target yields no verdict, not a default one.
        domain_str = api_tls.get("domain", "not resolved")
        basis_note = f" [{api_tls.get('domain_basis')}]" if api_tls.get("domain_basis") else ""
        results["findings"].append({
            "severity": "info",
            "issue": "App Backend API Unreachable — Not Assessed",
            "detail": f"Could not probe the app's API backend ({domain_str}{basis_note}). No cryptographic findings are reported for this app because none were observed.",
            "recommendation": "Verify the API domain resolves and is reachable, then re-run the scan. Provide the correct backend hostname if the automatic guess is wrong.",
        })
        results["pqc_score"] = None
        results["quantumSafe"] = None

    # 3. Store metadata finding
    if store_meta["version"] != "Unknown":
        results["findings"].append({
            "severity": "info",
            "issue": f"App Version Verified: {store_meta['version']}",
            "detail": f"Version {store_meta['version']} from {'App Store' if platform == 'iOS' else 'Play Store'}. Size: {store_meta['size']}.",
            "recommendation": None,
        })

    return results
