import socket
import ssl


def get_ssl_certificate(hostname, port=443):
    """Retrieve SSL certificate info for an HTTPS host."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert()
    except Exception as e:
        print(f"Could not retrieve SSL certificate for {hostname}: {e}")
        return None
