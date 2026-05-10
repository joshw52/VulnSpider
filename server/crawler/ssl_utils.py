import logging
import socket
import ssl
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# strptime format used by ssl.getpeercert() for notBefore / notAfter
_SSL_DATE_FMT = "%b %d %H:%M:%S %Y %Z"

# Signature algorithms considered weak
_WEAK_ALGORITHMS = {"md5", "sha1"}


def _analyze_certificate(cert: dict) -> dict:
    """
    Enrich a raw peercert dict with derived security findings.

    Adds:
      - ``expires_at``   ISO-8601 expiry timestamp
      - ``expired``      bool — True if the cert is already past its notAfter date
      - ``expiry_days``  int — days until expiry (negative if already expired)
      - ``weak_algorithm`` bool — True if the signature algorithm uses MD5 or SHA-1
      - ``issues``       list of human-readable problem strings
    """
    issues = []
    now = datetime.now(timezone.utc)

    # Expiry
    expires_at = None
    expiry_days = None
    expired = False
    not_after_raw = cert.get("notAfter")
    if not_after_raw:
        try:
            expires_at_dt = datetime.strptime(not_after_raw, _SSL_DATE_FMT).replace(tzinfo=timezone.utc)
            expires_at = expires_at_dt.isoformat()
            expiry_days = (expires_at_dt - now).days
            expired = expiry_days < 0
            if expired:
                issues.append(f"Certificate expired {abs(expiry_days)} day(s) ago")
            elif expiry_days <= 30:
                issues.append(f"Certificate expires in {expiry_days} day(s)")
        except ValueError:
            logger.warning("Could not parse certificate notAfter date: %s", not_after_raw)

    # Weak signature algorithm
    sig_alg = (cert.get("signatureAlgorithm") or "").lower()
    weak_algorithm = any(weak in sig_alg for weak in _WEAK_ALGORITHMS)
    if weak_algorithm:
        issues.append(f"Weak signature algorithm: {cert.get('signatureAlgorithm')}")

    return {
        **cert,
        "expires_at": expires_at,
        "expired": expired,
        "expiry_days": expiry_days,
        "weak_algorithm": weak_algorithm,
        "issues": issues,
    }


def get_ssl_certificate(hostname, port=443):
    """Retrieve and analyse SSL certificate info for an HTTPS host."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        return _analyze_certificate(cert)
    except ssl.SSLCertVerificationError as e:
        logger.warning("SSL certificate verification failed for %s: %s", hostname, e)
        return {"error": "certificate_verification_failed", "detail": str(e), "issues": [str(e)]}
    except ssl.SSLError as e:
        logger.warning("SSL error for %s: %s", hostname, e)
        return {"error": "ssl_error", "detail": str(e), "issues": [str(e)]}
    except socket.timeout:
        logger.warning("Timed out retrieving SSL certificate for %s", hostname)
        return {"error": "timeout", "detail": f"Connection to {hostname}:{port} timed out", "issues": []}
    except ConnectionRefusedError:
        logger.warning("Connection refused retrieving SSL certificate for %s:%s", hostname, port)
        return {"error": "connection_refused", "detail": f"Connection to {hostname}:{port} was refused", "issues": []}
    except OSError as e:
        logger.warning("Network error retrieving SSL certificate for %s: %s", hostname, e)
        return {"error": "network_error", "detail": str(e), "issues": []}
