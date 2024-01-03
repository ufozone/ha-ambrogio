"""Adds config flow for Ambrogio."""
import logging
import urllib.parse
import voluptuous as vol

from aiohttp import web_response

from homeassistant.components import http
from homeassistant.components.http.view import HomeAssistantView
from homeassistant.config_entries import (
    CONN_CLASS_CLOUD_POLL,
    ConfigFlow,
    FlowResult,
)
from homeassistant.const import (
    CONF_EMAIL,
    CONF_ERROR,
    CONF_PASSWORD,
    CONF_NAME,
)
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api.firebase import AmbrogioRobotException, AmbrogioRobotFirebaseAPI
from .const import (
    API_KEY,
    CONF_AUTH_PROVIDER,
    CONF_REFRESH_TOKEN,
    CONF_UID,
    DOMAIN,
)

_LOGGER: logging.Logger = logging.getLogger(__name__)

HEADER_FRONTEND_BASE = "HA-Frontend-Base"
AUTH_CALLBACK_PATH = "/auth/ambrogio_robot/callback"
AUTH_CALLBACK_NAME = "auth:ambrogio_robot:callback"


class AmbrogioFlowHandler(ConfigFlow, domain=DOMAIN):
    """Config flow for Ambrogio."""

    # Used to call the migration method if the verison changes.
    VERSION = 1
    CONNECTION_CLASS = CONN_CLASS_CLOUD_POLL
    auth_data: dict = {}

    async def async_step_user(self, user_input: dict | None = None) -> FlowResult:
        """Show the Setup Menu."""

        return self.async_show_menu(
            step_id="user",
            menu_options={
                "user_pass",
                "oauth",
                "manual",
            },
        )

    async def async_step_user_pass(self, user_input: dict | None = None) -> FlowResult:
        """Handle Firebase user/password signin."""
        _errors: dict[str, str] = {}

        if user_input is not None:
            api = AmbrogioRobotFirebaseAPI(async_get_clientsession(self.hass))
            try:
                response_json = await api.verify_password(
                    user_input[CONF_EMAIL], user_input[CONF_PASSWORD]
                )
            except AmbrogioRobotException as exp:
                _LOGGER.error("Google APIS Auth Failed: %s", exp)

            if CONF_ERROR in response_json:
                _errors["base"] = response_json[CONF_ERROR]
            else:
                # Get all the valid data from the response.
                self.auth_data = {
                    CONF_NAME: response_json["email"],
                    CONF_UID: response_json["localId"],
                    CONF_AUTH_PROVIDER: "user_password",
                    CONF_REFRESH_TOKEN: response_json["refreshToken"],
                }

                # Setup the Unique ID and check if already configured
                await self.async_set_unique_id(self.auth_data[CONF_NAME])
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=self.auth_data[CONF_NAME], data=self.auth_data
                )

        return self.async_show_form(
            step_id="user_pass",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_EMAIL,
                        default=(user_input or {}).get(CONF_EMAIL),
                    ): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.TEXT
                        ),
                    ),
                    vol.Required(
                        CONF_PASSWORD,
                        default=(user_input or {}).get(CONF_PASSWORD),
                    ): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.PASSWORD
                        ),
                    ),
                }
            ),
            errors=_errors,
            last_step=True,
        )

    async def async_step_oauth(self, user_input: dict | None = None) -> FlowResult:
        """Handle Google/ Apple OAuth signin."""
        if not user_input:
            self.hass.http.register_view(AmbrogioAuthorizationCallbackView)
            if (req := http.current_request.get()) is None:
                raise RuntimeError("No current request in context")
            if (hass_url := req.headers.get(HEADER_FRONTEND_BASE)) is None:
                raise RuntimeError("No header in request")

            self.hass.http.register_static_path(
                "/ambrogio_robot",
                self.hass.config.path(
                    "custom_components/ambrogio_robot/frontend/resources"
                ),
            )
            self.hass.http.register_static_path(
                "/ambrogio_robot/oauth",
                self.hass.config.path(
                    "custom_components/ambrogio_robot/frontend/firebase_auth.html"
                ),
            )

            forward_url = f"{hass_url}{AUTH_CALLBACK_PATH}?flow_id={self.flow_id}"
            AUTH_URL = "/ambrogio_robot/oauth?{}"
            parameters = {
                "forwardUrl": forward_url,
                "apiKey": API_KEY,
            }
            url = AUTH_URL.format(urllib.parse.urlencode(parameters))

            return self.async_external_step(
                step_id="oauth",
                url=url,
            )

        self.auth_data = user_input
        return self.async_external_step_done(next_step_id="oauth_finish")

    async def async_step_oauth_finish(
        self, user_input: dict | None = None
    ) -> FlowResult:
        """Handle the flow for the OAuth Finish process."""
        # Check this is unique
        await self.async_set_unique_id(self.auth_data[CONF_NAME])
        self._abort_if_unique_id_configured()

        return self.async_create_entry(
            title=self.auth_data[CONF_NAME], data=self.auth_data
        )

    async def async_step_manual(self, user_input: dict | None = None) -> FlowResult:
        """Handle Manual Configuration."""
        _errors: dict[str, str] = {}

        if user_input is not None:
            self.auth_data = {
                CONF_NAME: user_input[CONF_NAME],
                CONF_UID: user_input[CONF_UID],
                CONF_AUTH_PROVIDER: "manual",
            }

        _errors["base"] = "not_implemented"

        return self.async_show_form(
            step_id="manual",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_NAME,
                        default=(user_input or {}).get(CONF_NAME),
                    ): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.TEXT
                        ),
                    ),
                    vol.Required(
                        CONF_UID,
                        default=(user_input or {}).get(CONF_UID),
                    ): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.TEXT
                        ),
                    ),
                }
            ),
            errors=_errors,
            last_step=True,
        )


class AmbrogioAuthorizationCallbackView(HomeAssistantView):
    """Handle Callback from external auth."""

    url = AUTH_CALLBACK_PATH
    name = AUTH_CALLBACK_NAME
    requires_auth = False

    async def get(self, request):
        """Receive authorization confirmation."""
        hass = request.app["hass"]
        await hass.config_entries.flow.async_configure(
            flow_id=request.query["flow_id"],
            user_input={
                CONF_NAME: request.query["email"],
                CONF_AUTH_PROVIDER: request.query["provider"],
                CONF_UID: request.query["uid"],
                CONF_REFRESH_TOKEN: request.query["refreshToken"],
            },
        )

        return web_response.Response(
            headers={"content-type": "text/html"},
            text="<script>window.close()</script>Success! This window can be closed",
        )
