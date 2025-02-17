"""DataUpdateCoordinator for Ambrogio Robot."""
from __future__ import annotations

import asyncio
from datetime import (
    timedelta,
    datetime,
    UTC,
)
import pytz

from homeassistant.core import HomeAssistant
from homeassistant.const import (
    ATTR_ICON,
    ATTR_STATE,
    ATTR_LOCATION,
    ATTR_LATITUDE,
    ATTR_LONGITUDE,
    ATTR_MANUFACTURER,
    ATTR_MODEL,
    ATTR_SW_VERSION,
)
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
    UpdateFailed,
)
from homeassistant.exceptions import ConfigEntryAuthFailed

from .api.api import (
    AmbrogioRobotApiClient,
    AmbrogioRobotApiClientAuthenticationError,
    AmbrogioRobotApiClientError,
)
from .const import (
    LOGGER,
    DOMAIN,
    MANUFACTURER,
    API_DATETIME_FORMAT_DEFAULT,
    API_DATETIME_FORMAT_FALLBACK,
    API_ACK_TIMEOUT,
    UPDATE_INTERVAL_DEFAULT,
    UPDATE_INTERVAL_WORKING,
    CONF_ROBOT_NAME,
    CONF_ROBOT_IMEI,
    ATTR_SERIAL,
    ATTR_WORKING,
    ATTR_ERROR,
    ATTR_AVAILABLE,
    ATTR_CONNECTED,
    ATTR_LAST_COMM,
    ATTR_LAST_SEEN,
    ATTR_LAST_PULL,
    ATTR_LAST_STATE,
    ATTR_LAST_WAKE_UP,
    ROBOT_MODELS,
    ROBOT_STATES,
    ROBOT_WORKING_STATES,
    ROBOT_WAKE_UP_INTERVAL,
    ROBOT_ERRORS,
)


# https://developers.home-assistant.io/docs/integration_fetching_data#coordinated-single-api-poll-for-data-for-all-entities
class AmbrogioDataUpdateCoordinator(DataUpdateCoordinator):
    """Class to manage fetching data from the API."""

    def __init__(
        self,
        hass: HomeAssistant,
        robots: dict[str, str],
        client: AmbrogioRobotApiClient,
        update_interval: timedelta = timedelta(seconds=UPDATE_INTERVAL_DEFAULT),
    ) -> None:
        """Initialize."""
        super().__init__(
            hass=hass,
            logger=LOGGER,
            name=DOMAIN,
            update_interval=update_interval,
        )
        self.robots = robots
        self.client = client

        self.data = {}
        for robot_imei, robot_name in self.robots.items():
            self.data[robot_imei] = {
                CONF_ROBOT_NAME: robot_name,
                CONF_ROBOT_IMEI: robot_imei,
                ATTR_STATE: None,
                ATTR_ICON: None,
                ATTR_WORKING: False,
                ATTR_AVAILABLE: False,
                ATTR_ERROR: 0,
                ATTR_LOCATION: {},
                ATTR_SERIAL: None,
                ATTR_MANUFACTURER: MANUFACTURER,
                ATTR_MODEL: None,
                ATTR_SW_VERSION: None,
                ATTR_CONNECTED: False,
                ATTR_LAST_COMM: None,
                ATTR_LAST_SEEN: None,
                ATTR_LAST_PULL: None,
                ATTR_LAST_STATE: 0,
                ATTR_LAST_WAKE_UP: None,
            }
        self._loop = asyncio.get_event_loop()

    def _convert_datetime_from_api(
        self,
        date_string: str,
    ) -> datetime:
        """Convert datetime string from API data into datetime object."""
        try:
            return datetime.strptime(date_string, API_DATETIME_FORMAT_DEFAULT)
        except ValueError:
            return datetime.strptime(date_string, API_DATETIME_FORMAT_FALLBACK)

    def _get_datetime_now(self) -> datetime:
        """Get current datetime in UTC."""
        return datetime.utcnow().replace(tzinfo=UTC)

    def _get_datetime_from_duration(
        self,
        duration: int,
    ) -> datetime:
        """Get datetime object by adding a duration to the current time."""
        locale_timezone = pytz.timezone(str(self.hass.config.time_zone))
        datetime_now = datetime.utcnow().astimezone(locale_timezone)
        return datetime_now + timedelta(minutes=duration)

    async def __aenter__(self):
        """Return Self."""
        return self

    async def __aexit__(self, *excinfo):
        """Close Session before class is destroyed."""
        await self.client._session.close()

    async def _async_update_data(self):
        """Update data via library."""
        try:
            # Update all mowers.
            await self.async_fetch_all_mowers()

            # TODO
            LOGGER.debug("_async_update_data")
            LOGGER.debug(self.data)

            # If one or more lawn mower(s) working, increase update_interval
            if self.has_working_mowers():
                suggested_update_interval = timedelta(seconds=UPDATE_INTERVAL_WORKING)
            else:
                suggested_update_interval = timedelta(seconds=UPDATE_INTERVAL_DEFAULT)
            # Set suggested update_interval
            if suggested_update_interval != self.update_interval:
                self.update_interval = suggested_update_interval
                LOGGER.info(
                    "Update update_interval, because lawn mower(s) "
                    "changed state from not working to working or vice versa."
                )
            return self.data
        except AmbrogioRobotApiClientAuthenticationError as exception:
            raise ConfigEntryAuthFailed(exception) from exception
        except AmbrogioRobotApiClientError as exception:
            raise UpdateFailed(exception) from exception

    async def _async_update_listeners(self) -> None:
        """Update all registered listeners."""
        self.async_update_listeners()

    def get_mower_attributes(
        self,
        imei: str,
    ) -> dict[str, any] | None:
        """Get attributes of an given lawn mower."""
        return self.data.get(imei, None)

    def has_working_mowers(
        self,
    ) -> bool:
        """Count the working lawn mowers."""
        count_helper = [v["working"] for k, v in self.data.items() if v.get("working")]
        return len(count_helper) > 0

    async def async_fetch_all_mowers(
        self,
    ) -> None:
        """Fetch data for all mowers."""
        mower_imeis = list(self.data.keys())
        if len(mower_imeis) == 0:
            return None

        await self.client.execute(
            "thing.list",
            {
                "show": [
                    "id",
                    "key",
                    "name",
                    "connected",
                    "lastSeen",
                    "lastCommunication",
                    "loc",
                    "properties",
                    "alarms",
                    "attrs",
                    "createdOn",
                    "storage",
                    "varBillingPlanCode",
                ],
                "hideFields": True,
                "keys": mower_imeis,
            },
        )
        response = await self.client.get_response()
        if "result" in response:
            result_list = response["result"]
            for mower in (
                mower
                for mower in result_list
                if "key" in mower and mower["key"] in self.data
            ):
                await self.async_update_mower(mower)

    async def async_fetch_single_mower(
        self,
        imei: str,
    ) -> bool:
        """Fetch data for single mower, return connection state."""
        await self.client.execute(
            "thing.find",
            {
                "imei": imei,
            },
        )
        response = await self.client.get_response()
        await self.async_update_mower(response)

        # Always update HA states after a command was executed.
        # API calls that change the lawn mower's state update the local object when
        # executing the command, so only the HA state needs further updates.
        self.hass.async_create_task(self._async_update_listeners())
        return response.get("connected", False)

    async def async_update_mower(
        self,
        data: dict[str, any],
    ) -> None:
        """Update a single mower."""
        imei = data.get("key", "")
        mower = self.get_mower_attributes(imei)
        if mower is None:
            return None
        # Start refreshing mower in coordinator from fetched API data
        if "alarms" in data and "robot_state" in data["alarms"]:
            robot_state = data["alarms"]["robot_state"]
            _state = (
                robot_state["state"] if robot_state["state"] < len(ROBOT_STATES) else 0
            )
            mower[ATTR_STATE] = ROBOT_STATES[_state]["name"]
            mower[ATTR_ICON] = ROBOT_STATES[_state]["icon"]
            mower[ATTR_WORKING] = _state in list(ROBOT_WORKING_STATES)
            mower[ATTR_AVAILABLE] = _state > 0
            # msg not always available
            if "msg" in robot_state:
                mower[ATTR_ERROR] = ROBOT_ERRORS.get(int(robot_state["msg"]), None)
            # latitude and longitude not always available
            if "lat" in robot_state and "lng" in robot_state:
                mower[ATTR_LOCATION] = {
                    ATTR_LATITUDE: robot_state["lat"],
                    ATTR_LONGITUDE: robot_state["lng"],
                }
        if "attrs" in data:
            # In some cases, robot_serial is not available
            if "robot_serial" in data["attrs"]:
                mower[ATTR_SERIAL] = data["attrs"]["robot_serial"]["value"]
                if len(mower[ATTR_SERIAL]) > 5:
                    mower[ATTR_MODEL] = mower[ATTR_SERIAL][0:6]
                    if mower[ATTR_MODEL] in ROBOT_MODELS:
                        mower[ATTR_MODEL] = ROBOT_MODELS[mower[ATTR_MODEL]]
            # In some cases, program_version is not available
            if "program_version" in data["attrs"]:
                _revision = data["attrs"]["program_version"]["value"]
                mower[ATTR_SW_VERSION] = f"r{_revision}"
        mower[ATTR_CONNECTED] = data.get("connected", False)
        if "lastCommunication" in data:
            mower[ATTR_LAST_COMM] = self._convert_datetime_from_api(
                data["lastCommunication"]
            )
        if "lastSeen" in data:
            mower[ATTR_LAST_SEEN] = self._convert_datetime_from_api(data["lastSeen"])
        mower[ATTR_LAST_PULL] = self._get_datetime_now()

        # If lawn mower is working send a wake_up command every ROBOT_WAKE_UP_INTERVAL seconds
        if mower.get(ATTR_STATE) in ROBOT_WORKING_STATES and (
            mower.get(ATTR_LAST_WAKE_UP) is None
            or (self._get_datetime_now() - mower.get(ATTR_LAST_WAKE_UP)).total_seconds()
            > ROBOT_WAKE_UP_INTERVAL
        ):
            self.hass.async_create_task(self.async_wake_up(imei))
        # State changed
        if mower.get(ATTR_STATE) != mower.get(ATTR_LAST_STATE):
            # If lawn mower is now working send trace_position command
            if mower.get(ATTR_STATE) in ROBOT_WORKING_STATES:
                self.hass.async_create_task(self.async_trace_position(imei))
            # Set new state to last stateus
            mower[ATTR_LAST_STATE] = mower.get(ATTR_STATE)

        self.data[imei] = mower

    async def async_prepare_for_command(
        self,
        imei: str,
    ) -> bool:
        """Prepare lawn mower for incomming command."""
        try:
            # Use connection state from last fetch if last pull was not longer than 10 seconds ago
            mower = self.get_mower_attributes(imei)
            last_pull = mower.get(ATTR_LAST_PULL, None)
            if (
                last_pull is not None
                and (self._get_datetime_now() - last_pull).total_seconds() < 10
                and mower.get(ATTR_CONNECTED, False)
            ):
                return True

            # Fetch connection state fresh from API
            connected = await self.async_fetch_single_mower(imei)
            if connected is True:
                return True

            # Send wake up command if last attempt was more than 60 seconds ago
            if (
                mower.get(ATTR_LAST_WAKE_UP) is None
                or (
                    self._get_datetime_now() - mower.get(ATTR_LAST_WAKE_UP)
                ).total_seconds()
                > 60
            ):
                await self.async_wake_up(imei)

            # Wait 5 seconds before the loop starts
            await asyncio.sleep(5)

            attempt = 0
            while connected is False and attempt <= 5:
                connected = await self.async_fetch_single_mower(imei)
                if connected is True:
                    return True
                attempt = attempt + 1
                # Wait 5 seconds before next attempt
                await asyncio.sleep(5)
            raise asyncio.TimeoutError(
                f"The lawn mower with IMEI {imei} was not available after a long wait"
            )
        except Exception as exception:
            LOGGER.exception(exception)

    async def async_wake_up(
        self,
        imei: str,
    ) -> bool:
        """Send command wake_up to lawn nower."""
        LOGGER.debug("wake_up: %s", imei)
        try:
            self.data[imei][ATTR_LAST_WAKE_UP] = self._get_datetime_now()
            return await self.client.execute(
                "sms.send",
                {
                    "coding": "SEVEN_BIT",
                    "imei": imei,
                    "message": "UP",
                },
            )
        except Exception as exception:
            LOGGER.exception(exception)
        return False

    async def async_set_profile(
        self,
        imei: str,
        profile: int,
    ) -> bool:
        """Send command set_profile to lawn nower."""
        LOGGER.debug("set_profile: %s", imei)
        try:
            await self.async_prepare_for_command(imei)
            return await self.client.execute(
                "method.exec",
                {
                    "method": "set_profile",
                    "imei": imei,
                    "params": {
                        "profile": (profile - 1),
                    },
                    "ackTimeout": API_ACK_TIMEOUT,
                    "singleton": True,
                },
            )
        except Exception as exception:
            LOGGER.exception(exception)

    async def async_work_now(
        self,
        imei: str,
    ) -> bool:
        """Send command work_now to lawn nower."""
        LOGGER.debug("work_now: %s", imei)
        try:
            await self.async_prepare_for_command(imei)
            return await self.client.execute(
                "method.exec",
                {
                    "method": "work_now",
                    "imei": imei,
                    "ackTimeout": API_ACK_TIMEOUT,
                    "singleton": True,
                },
            )
        except Exception as exception:
            LOGGER.exception(exception)

    async def async_work_for(
        self,
        imei: str,
        duration: int,
        area: int | None = None,
    ) -> bool:
        """Prepare command work_for."""
        LOGGER.debug("work_for: %s", imei)
        _target = self._get_datetime_from_duration(duration)
        await self.async_work_until(
            imei=imei,
            hours=_target.hour,
            minutes=_target.minute,
            area=area,
        )

    async def async_work_until(
        self,
        imei: str,
        hours: int,
        minutes: int,
        area: int | None = None,
    ) -> bool:
        """Send command work_until to lawn nower."""
        LOGGER.debug("work_until: %s", imei)
        _params = {
            "hh": hours,
            "mm": minutes,
        }
        if isinstance(area, int) and area in range(1, 10):
            _params["area"] = area - 1
        else:
            _params["area"] = 255
        try:
            await self.async_prepare_for_command(imei)
            return await self.client.execute(
                "method.exec",
                {
                    "method": "work_until",
                    "imei": imei,
                    "params": _params,
                    "ackTimeout": API_ACK_TIMEOUT,
                    "singleton": True,
                },
            )
        except Exception as exception:
            LOGGER.exception(exception)

    async def async_border_cut(
        self,
        imei: str,
    ) -> bool:
        """Send command border_cut to lawn nower."""
        LOGGER.debug("border_cut: %s", imei)
        try:
            await self.async_prepare_for_command(imei)
            return await self.client.execute(
                "method.exec",
                {
                    "method": "border_cut",
                    "imei": imei,
                    "ackTimeout": API_ACK_TIMEOUT,
                    "singleton": True,
                },
            )
        except Exception as exception:
            LOGGER.exception(exception)

    async def async_charge_now(
        self,
        imei: str,
    ) -> bool:
        """Send command charge_now to lawn nower."""
        LOGGER.debug("charge_now: %s", imei)
        try:
            await self.async_prepare_for_command(imei)
            return await self.client.execute(
                "method.exec",
                {
                    "method": "charge_now",
                    "imei": imei,
                    "ackTimeout": API_ACK_TIMEOUT,
                    "singleton": True,
                },
            )
        except Exception as exception:
            LOGGER.exception(exception)

    async def async_charge_for(
        self,
        imei: str,
        duration: int,
    ) -> bool:
        """Prepare command charge_until."""
        _target = self._get_datetime_from_duration(duration)
        await self.async_charge_until(
            imei=imei,
            hours=_target.hour,
            minutes=_target.minute,
            weekday=_target.isoweekday(),
        )

    async def async_charge_until(
        self,
        imei: str,
        hours: int,
        minutes: int,
        weekday: int,
    ) -> bool:
        """Send command charge_until to lawn nower."""
        LOGGER.debug("charge_until: %s", imei)
        try:
            await self.async_prepare_for_command(imei)
            return await self.client.execute(
                "method.exec",
                {
                    "method": "charge_until",
                    "imei": imei,
                    "params": {
                        "hh": hours,
                        "mm": minutes,
                        "weekday": (weekday - 1),
                    },
                    "ackTimeout": API_ACK_TIMEOUT,
                    "singleton": True,
                },
            )
        except Exception as exception:
            LOGGER.exception(exception)

    async def async_trace_position(
        self,
        imei: str,
    ) -> bool:
        """Send command trace_position to lawn nower."""
        LOGGER.debug("trace_position: %s", imei)
        try:
            await self.async_prepare_for_command(imei)
            return await self.client.execute(
                "method.exec",
                {
                    "method": "trace_position",
                    "imei": imei,
                    "ackTimeout": API_ACK_TIMEOUT,
                    "singleton": True,
                },
            )
        except Exception as exception:
            LOGGER.exception(exception)

    async def async_keep_out(
        self,
        imei: str,
        latitude: float,
        longitude: float,
        radius: int,
        hours: int | None = None,
        minutes: int | None = None,
        index: int | None = None,
    ) -> bool:
        """Send command keep_out to lawn nower."""
        LOGGER.debug("keep_out: %s", imei)
        _params = {
            "latitude": latitude,
            "longitude": longitude,
            "radius": radius,
        }
        if isinstance(hours, int) and hours in range(0, 23):
            _params["hh"] = hours
        if isinstance(minutes, int) and minutes in range(0, 59):
            _params["mm"] = minutes
        if isinstance(index, int):
            _params["index"] = index
        try:
            await self.async_prepare_for_command(imei)
            return await self.client.execute(
                "method.exec",
                {
                    "method": "keep_out",
                    "imei": imei,
                    "params": _params,
                    "ackTimeout": API_ACK_TIMEOUT,
                    "singleton": True,
                },
            )
        except Exception as exception:
            LOGGER.exception(exception)

    async def async_custom_command(
        self,
        imei: str,
        command: str,
        params: dict[str, any] | list[any] | None = None,
    ) -> bool:
        """Send custom command to lawn nower."""
        try:
            await self.async_prepare_for_command(imei)
            return await self.client.execute(
                "method.exec",
                {
                    "method": command,
                    "imei": imei,
                    "params": params,
                    "ackTimeout": API_ACK_TIMEOUT,
                    "singleton": True,
                },
            )
        except Exception as exception:
            LOGGER.exception(exception)
