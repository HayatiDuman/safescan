import httpx


async def scan(url: str, client: httpx.AsyncClient):
    try:
        response = await client.get(url, timeout=5.0)

        # Raw header parsing to avoid httpx cookie jar issues
        set_cookie_headers = response.headers.get_list("set-cookie")

        if not set_cookie_headers:
            return {
                "scanner": "Cookies",
                "status": "Secure",
                "severity": "Info",
                "detail": "The website does not use cookies."
            }

        issues = []

        for header in set_cookie_headers:
            header_lower = header.lower()

            # Extract cookie name from "name=value"
            cookie_name = header.split("=")[0].strip()

            cookie_issues = []

            # Security flag checks
            if "httponly" not in header_lower:
                cookie_issues.append("Missing HttpOnly")

            if "secure" not in header_lower:
                cookie_issues.append("Missing Secure")

            if "samesite" not in header_lower:
                cookie_issues.append("Missing SameSite (CSRF risk)")

            if cookie_issues:
                issues.append(f"'{cookie_name}': {', '.join(cookie_issues)}")

        if issues:
            return {
                "scanner": "Cookies",
                "status": "Vulnerability Found",
                "severity": "Low",  # Preserved original threat level
                "detail": f"Cookies missing Secure, HttpOnly, or SameSite flags: {' | '.join(issues)}"
            }

        return {
            "scanner": "Cookies",
            "status": "Secure",
            "severity": "Info",
            "detail": "All cookies have secure flags."
        }

    except Exception as e:
        # Detailed exception handling format
        return {
            "scanner": "Cookies",
            "status": "Error",
            "severity": "Info",
            "detail": f"{type(e).__name__}: {e}"
        }