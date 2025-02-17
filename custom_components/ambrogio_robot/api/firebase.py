"""The API for accessing firebase used by the App."""
import logging

from urllib.parse import urljoin
import json

import aiohttp

_LOGGER: logging.Logger = logging.getLogger(__name__)

GOOGLEAPIS_URL = "https://identitytoolkit.googleapis.com"
VERIFY_PASSWORD = "/v1/accounts:signInWithPassword"

FIREBASE_URL = "wss://centrosistemi-ambrogioremote.firebaseio.com"
FIREBASE_DB = "centrosistemi-ambrogioremote"
FIREBASE_VER = "5"

API_KEY = "AIzaSyCUGSbVrwZ3X7BHU6oiUSmdzQwx-QXypUI"


class AmbrogioRobotException(Exception):
    """Exception Ambrogio Exceptions."""

    def __init__(self, status, message):
        """Initialize."""
        super().__init__(status)
        self.status = status
        self.message = message


class AmbrogioRobotFirebaseAPI:
    """Client for the Ambrogio Firebase API."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
    ) -> None:
        """Initiate Firebase API."""
        self._session = session

    async def verify_password(self, email: str, password: str) -> dict:
        """Verify the username and password with the googleapis site."""
        auth_data: dict = {
            "email": email,
            "password": password,
            "returnSecureToken": "true",
        }

        response = await self._session.post(
            urljoin(
                GOOGLEAPIS_URL,
                f"{VERIFY_PASSWORD}?key={API_KEY}",
            ),
            data=json.dumps(auth_data),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9;",
            },
        )

        response_json = await response.json()
        if "error" in response_json:
            raise AmbrogioRobotException(
                response_json["error"]["code"], response_json["error"]["message"]
            )

        return response_json

    async def get_robots(self, access_token: str, api_token: str) -> dict:
        """Get the Garage Robots."""
        robot_list = {}
        async with self._session.ws_connect(
            urljoin(FIREBASE_URL, f".ws?ns={FIREBASE_DB}&v={FIREBASE_VER}")
        ) as ws_api:
            # Receive response from connection.
            response_json = await ws_api.receive_json()
            _LOGGER.debug("WS Connect Response: %s", response_json)
            check = response_json["d"]["d"]
            if not isinstance(check, dict):
                _LOGGER.error("WS Connect Error: %s", check)
                raise AmbrogioRobotException(1, check)

            # Authorize the Session Token
            send_msg = (
                '{"t":"d","d":{"a":"auth","r":1,"b":{"cred":"' + access_token + '"}}}'
            )
            await ws_api.send_str(send_msg)

            # Authorize response should be "ok"
            response_json = await ws_api.receive_json()
            _LOGGER.debug("WS Auth Response: %s", response_json)
            if response_json["d"]["b"]["s"] != "ok":
                _LOGGER.error("WS Auth Failed.")

            # Request the Robot List
            send_msg = (
                '{"t":"d","d":{"a":"q","r":2,"b":{"p":"robots\\/ambrogio\\/'
                + api_token
                + '","h":""}}}'
            )
            await ws_api.send_str(send_msg)

            # Should respond with list of robots.
            response_json = await ws_api.receive_json()
            _LOGGER.debug("WS Robot List Response: %s", response_json)

            await ws_api.close()

            # Robots are under d->b->d, shoudl return a list.
            robot_list = response_json["d"]["b"]["d"]

        return robot_list
