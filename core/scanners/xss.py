import httpx
from urllib.parse import urlparse, parse_qs, urlunparse

# Multi-variant XSS payload set
# Includes event handlers, tag breaking, and encoding variants
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",

    # HTML entity encoding attempts (WAF bypass)
    "&lt;script&gt;alert(1)&lt;/script&gt;",
]

# Signature-based detection patterns
# Looks for characteristic fragments instead of the full payload
DETECTION_SIGNATURES = [
    "onerror=alert",
    "onload=alert",
    "<script>alert",
    "javascript:alert",
    "<svg onload",
]


async def _test_param(
    client: httpx.AsyncClient,
    base_url: str,
    params: dict,
    param_name: str
):
    """
    Tests a single parameter with all XSS payloads
    (Targeted Parameter Testing).
    """

    for payload in XSS_PAYLOADS:
        test_params = params.copy()
        test_params[param_name] = payload

        try:
            # httpx automatically handles URL encoding
            response = await client.get(
                base_url,
                params=test_params,
                timeout=7.0
            )

            body = response.text

            # Stage 1: Check if the full payload is reflected
            if payload in body:
                return (
                    payload,
                    "Full payload reflected without filtering"
                )

            # Stage 2: Signature-based detection
            for sig in DETECTION_SIGNATURES:
                if sig.lower() in body.lower():
                    return (
                        payload,
                        f"Partial signature detected (`{sig}`)"
                    )

        except Exception:
            continue

    return None, None


async def scan(url: str, client: httpx.AsyncClient):
    try:
        # Dynamically extract URL parameters
        parsed = urlparse(url)

        existing_params = parse_qs(parsed.query)

        params_to_test = {
            k: v[0]
            for k, v in existing_params.items()
        }

        # Default blind-testing targets if no parameters exist
        if not params_to_test:
            params_to_test = {
                "q": "test",
                "search": "test",
                "id": "1",
                "name": "test"
            }

        base_url = urlunparse(parsed._replace(query=""))

        findings = []

        for param_name in params_to_test:
            payload, reason = await _test_param(
                client,
                base_url,
                params_to_test,
                param_name
            )

            if payload:
                findings.append(
                    f"Reflected XSS detected in parameter "
                    f"'{param_name}'! ({reason})"
                )

        if findings:
            return {
                "scanner": "XSS",
                "status": "Vulnerability Found",
                "severity": "High",
                "detail": " | ".join(findings)
            }

        return {
            "scanner": "XSS",
            "status": "Secure",
            "severity": "Info",
            "detail": (
                f"{len(XSS_PAYLOADS)} payloads tested against "
                f"parameters {list(params_to_test.keys())}. "
                f"No XSS vulnerability detected."
            )
        }

    except Exception as e:
        # Standardized exception formatting
        error_msg = (
            f"{type(e).__name__}: {str(e)}"
            if str(e)
            else type(e).__name__
        )

        return {
            "scanner": "XSS",
            "status": "Error",
            "severity": "Info",
            "detail": error_msg
        }