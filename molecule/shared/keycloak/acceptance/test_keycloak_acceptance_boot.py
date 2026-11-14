"""Offline boot regression using the acceptance application's real dependencies.

Run with the isolated Python environment installed from
``molecule/shared/keycloak/acceptance/requirements.txt``:
``python -m unittest discover -s molecule/shared/keycloak/acceptance -p test_keycloak_acceptance_boot.py``.
This does not exercise the protected Incus/browser acceptance journey.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

APPLICATION = Path(__file__).resolve().parent


class KeycloakAcceptanceBootTests(unittest.TestCase):
    def test_gunicorn_import_and_local_routes_need_no_identity_provider(self) -> None:
        environment = {
            **os.environ,
            "OIDC_SESSION_SECRET": "offline-test-session-secret",
            "OIDC_ISSUER": "https://identity-provider.invalid/realms/offline",
            "OIDC_CLIENT_ID": "offline-acceptance",
            "OIDC_CLIENT_SECRET": "offline-test-client-secret",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        # Gunicorn's actual application loader follows the same Authlib import
        # chain as the systemd worker. Missing optional client dependencies must
        # fail here; importing the application is never stubbed or skipped.
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from gunicorn.util import import_app\n"
                "app = import_app('protected_app:app')\n"
                "app.testing = True\n"
                "client = app.test_client()\n"
                "health = client.get('/healthz')\n"
                "assert health.status_code == 200, health.status_code\n"
                "assert health.get_json() == {'status': 'ok'}, health.data\n"
                "assert health.headers['Cache-Control'] == 'no-store'\n"
                "assert client.get('/').status_code == 200\n"
                "for route in ('/viewer', '/admin'):\n"
                "    denied = client.get(route)\n"
                "    assert denied.status_code == 302, (route, denied.status_code)\n"
                "    assert denied.headers['Location'] == '/login', denied.headers\n",
            ],
            cwd=APPLICATION,
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
