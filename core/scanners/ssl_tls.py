import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
import httpx


async def scan(url: str, client: httpx.AsyncClient):

    # Validate URL format
    if not url.startswith(("http://", "https://")):
        return {
            "scanner": "SSL/TLS",
            "status": "Error",
            "severity": "Info",
            "detail": "Invalid URL format."
        }

    # Warn if the site uses unencrypted HTTP
    if url.startswith("http://"):
        return {
            "scanner": "SSL/TLS",
            "status": "Vulnerability Found",
            "severity": "High",
            "detail": (
                "The connection uses unencrypted HTTP. "
                "All traffic is transmitted in plain text. "
                "HTTPS should be used."
            )
        }

    parsed = urlparse(url)

    hostname = parsed.hostname
    port = parsed.port or 443

    issues = []
    details = []

    try:
        # Low-level socket handshake for direct TLS inspection
        ctx = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port),
            timeout=5
        ) as sock:

            with ctx.wrap_socket(
                sock,
                server_hostname=hostname
            ) as ssock:

                cert = ssock.getpeercert()

                # Example: TLSv1.2 / TLSv1.3
                tls_version = ssock.version()

                details.append(
                    f"TLS Version: {tls_version}"
                )

                # Detect deprecated or insecure protocols
                if tls_version in (
                    "TLSv1",
                    "TLSv1.1",
                    "SSLv2",
                    "SSLv3"
                ):
                    issues.append(
                        f"{tls_version} is being used "
                        f"(deprecated/insecure)"
                    )

                # Certificate expiration validation
                not_after_str = cert.get("notAfter", "")

                if not_after_str:

                    # Example format:
                    # "May  5 12:00:00 2025 GMT"
                    not_after = datetime.strptime(
                        not_after_str,
                        "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)

                    now = datetime.now(timezone.utc)

                    days_left = (not_after - now).days

                    details.append(
                        f"Certificate Expiration: "
                        f"{not_after.strftime('%Y-%m-%d')} "
                        f"({days_left} days remaining)"
                    )

                    if days_left < 0:
                        issues.append(
                            "Certificate has EXPIRED!"
                        )

                    elif days_left < 30:
                        issues.append(
                            f"Certificate will expire in "
                            f"{days_left} days!"
                        )

                # Subject Alternative Names (SAN) validation
                san = cert.get("subjectAltName", [])

                details.append(
                    f"SAN Record Count: {len(san)}"
                )

        detail_str = " | ".join(details)

        if issues:
            return {
                "scanner": "SSL/TLS",
                "status": "Vulnerability Found",
                "severity": "High",
                "detail": (
                    f"Issues: {', '.join(issues)} "
                    f"| {detail_str}"
                )
            }

        return {
            "scanner": "SSL/TLS",
            "status": "Secure",
            "severity": "Info",
            "detail": (
                f"HTTPS is securely configured. "
                f"{detail_str}"
            )
        }

    except ssl.SSLCertVerificationError as e:
        # Handles self-signed or invalid certificates
        return {
            "scanner": "SSL/TLS",
            "status": "Vulnerability Found",
            "severity": "Critical",
            "detail": (
                f"Certificate verification FAILED "
                f"(may be self-signed or invalid): {e}"
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
            "scanner": "SSL/TLS",
            "status": "Error",
            "severity": "Info",
            "detail": error_msg
        }