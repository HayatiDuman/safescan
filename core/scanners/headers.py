import httpx

# Seven critical security headers and their descriptions
SECURITY_HEADERS = [
    ("x-frame-options", "Clickjacking protection"),
    ("x-content-type-options", "MIME-type sniffing protection"),
    ("content-security-policy", "XSS and injection protection (CSP)"),
    ("strict-transport-security", "HTTPS enforcement (HSTS)"),
    ("referrer-policy", "Referrer information leak protection"),
    ("permissions-policy", "Browser API access control"),
    ("x-xss-protection", "Legacy XSS filter (for older browsers)"),
]


async def scan(url: str, client: httpx.AsyncClient):
    try:
        response = await client.get(url, timeout=5.0)

        headers = {
            k.lower(): v
            for k, v in response.headers.items()
        }

        is_https = url.startswith("https")

        missing = []

        for header_name, description in SECURITY_HEADERS:

            # Skip HSTS checks for non-HTTPS websites
            if header_name == "strict-transport-security" and not is_https:
                continue

            if header_name not in headers:
                missing.append(f"{header_name} ({description})")

        # Deep CSP inspection
        csp_issues = []

        if "content-security-policy" in headers:
            csp = headers["content-security-policy"].lower()

            if "'unsafe-inline'" in csp:
                csp_issues.append(
                    "CSP contains 'unsafe-inline' "
                    "(weakens XSS protection)"
                )

            if "'unsafe-eval'" in csp:
                csp_issues.append(
                    "CSP contains 'unsafe-eval'"
                )

        all_issues = missing + csp_issues

        if all_issues:

            # Dynamic severity calculation
            severity = (
                "High"
                if len(missing) >= 3 or csp_issues
                else "Medium"
            )

            return {
                "scanner": "Security Headers",
                "status": "Vulnerability Found",
                "severity": severity,
                "detail": (
                    f"Missing/problematic headers: "
                    f"{' | '.join(all_issues)}"
                )
            }

        return {
            "scanner": "Security Headers",
            "status": "Secure",
            "severity": "Info",
            "detail": (
                "All critical security headers are present "
                "and CSP is secure."
            )
        }

    except Exception as e:
        # Standardized detailed error handling
        return {
            "scanner": "Security Headers",
            "status": "Error",
            "severity": "Info",
            "detail": f"{type(e).__name__}: {str(e)}"
        }