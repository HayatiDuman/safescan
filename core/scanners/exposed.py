import httpx
import asyncio
from urllib.parse import urlparse

# Extended sensitive file dictionary
SENSITIVE_PATHS = {
    "Config/Env": [
        "/.env",
        "/.env.backup",
        "/.env.production",
        "/config.php",
        "/configuration.php",
        "/settings.py"
    ],

    "Version Control": [
        "/.git/config",
        "/.git/HEAD",
        "/.svn/entries"
    ],

    "Debug/Info": [
        "/phpinfo.php",
        "/info.php",
        "/test.php",
        "/debug.php",
        "/server-status"
    ],

    "Admin Panels": [
        "/admin",
        "/admin/",
        "/wp-admin/",
        "/administrator/",
        "/phpmyadmin/",
        "/adminer.php"
    ],

    "Backup Files": [
        "/backup.zip",
        "/backup.sql",
        "/db.sql",
        "/dump.sql"
    ],

    "Crawl Data": [
        "/robots.txt",
        "/sitemap.xml",
        "/.DS_Store"
    ],
}


async def _check_path(client: httpx.AsyncClient, base_url: str, path: str):
    try:
        res = await client.get(
            f"{base_url}{path}",
            timeout=4.0,
            follow_redirects=False
        )

        if res.status_code not in (200, 206):
            return None

        content_type = res.headers.get("content-type", "").lower()
        body = res.text[:500].lower()

        # False positive filter
        html_error_indicators = [
            "<!doctype html",
            "<html",
            "404",
            "not found",
            "error",
            "forbidden",
            "unauthorized",
            "page not found"
        ]

        if "text/html" in content_type:
            if any(indicator in body for indicator in html_error_indicators):
                return None

            # HTML responses are suspicious unless the file is expected to be HTML/PHP
            if not any(path.endswith(ext) for ext in [".php", ".html", ".htm"]):
                return None

        # Additional HTML response validation layer
        elif "<html" in res.text[:20].lower() and not any(
            path.endswith(ext) for ext in [".php", ".html", ".htm"]
        ):
            return None

        # Skip very short or empty responses
        if len(res.text.strip()) < 20:
            return None

        return path

    except Exception:
        pass

    return None


async def scan(url: str, client: httpx.AsyncClient):
    # Extract and normalize the root URL
    parsed = urlparse(url)
    root_url = f"{parsed.scheme}://{parsed.netloc}"

    all_paths = [
        path
        for paths in SENSITIVE_PATHS.values()
        for path in paths
    ]

    try:
        # Run all checks asynchronously
        tasks = [
            _check_path(client, root_url, path)
            for path in all_paths
        ]

        results = await asyncio.gather(*tasks)

        found_paths = [p for p in results if p is not None]

        if found_paths:
            found_categories = []

            for category, paths in SENSITIVE_PATHS.items():
                if any(p in found_paths for p in paths):
                    found_categories.append(category)

            # Increase severity for critical exposed files
            severity = (
                "Critical"
                if any(
                    p in found_paths
                    for p in ["/.env", "/.git/config", "/backup.sql"]
                )
                else "Medium"
            )

            return {
                "scanner": "Exposed Files",
                "status": "Vulnerability Found",
                "severity": severity,
                "detail": (
                    f"Exposed files detected "
                    f"({', '.join(found_categories)}): "
                    f"{', '.join(found_paths)}"
                )
            }

        return {
            "scanner": "Exposed Files",
            "status": "Secure",
            "severity": "Info",
            "detail": (
                f"{len(all_paths)} paths checked. "
                f"No sensitive file exposure detected."
            )
        }

    except Exception as e:
        # Detailed error formatting
        error_msg = (
            f"{type(e).__name__}: {str(e)}"
            if str(e)
            else type(e).__name__
        )

        return {
            "scanner": "Exposed Files",
            "status": "Error",
            "severity": "Info",
            "detail": error_msg
        }