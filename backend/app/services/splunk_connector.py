"""
Splunk REST API connector for ES and SOAR integration.

Handles:
- Connection testing
- ES correlation search retrieval
- SOAR playbook/action run log querying
"""
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from urllib.parse import urljoin
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.splunk_config import SplunkConfig
from app.core.encryption import decrypt_secret

logger = logging.getLogger(__name__)


class SplunkConnectorError(Exception):
    """Base exception for Splunk connector errors."""
    pass


class SplunkAuthError(SplunkConnectorError):
    """Authentication failure."""
    pass


class SplunkConnectionError(SplunkConnectorError):
    """Connection failure."""
    pass


class SplunkConnector:
    """
    Async Splunk REST API client.

    Supports both token and basic authentication.
    Handles ES saved searches and SOAR execution logs.
    """

    def __init__(
        self,
        base_url: str,
        auth_type: str = "token",
        auth_token: Optional[str] = None,
        auth_username: Optional[str] = None,
        auth_password: Optional[str] = None,
        verify_tls: bool = True,
        es_app_namespace: str = "SplunkEnterpriseSecuritySuite",
        es_owner: str = "nobody",
        timeout: float = 60.0,
    ):
        """
        Initialize Splunk connector.

        Args:
            base_url: Splunk REST API base URL (e.g., https://splunk-sh:8089)
            auth_type: "token" or "basic"
            auth_token: Bearer token for token auth
            auth_username: Username for basic auth
            auth_password: Password for basic auth
            verify_tls: Whether to verify TLS certificates
            es_app_namespace: Splunk ES app namespace
            es_owner: Splunk owner for ES saved searches
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.auth_type = auth_type
        self.auth_token = auth_token
        self.auth_username = auth_username
        self.auth_password = auth_password
        self.verify_tls = verify_tls
        self.es_app_namespace = es_app_namespace
        self.es_owner = es_owner
        self.timeout = timeout

    @classmethod
    async def from_config(cls, db: AsyncSession, config_id: Optional[int] = None) -> "SplunkConnector":
        """
        Create connector from stored SplunkConfig.

        Args:
            db: Database session
            config_id: Specific config ID, or None for active config

        Returns:
            Configured SplunkConnector instance

        Raises:
            SplunkConnectionError: If no config found
        """
        if config_id:
            stmt = select(SplunkConfig).where(SplunkConfig.id == config_id)
        else:
            stmt = select(SplunkConfig).where(SplunkConfig.is_active == True)

        result = await db.execute(stmt)
        config = result.scalar_one_or_none()

        if not config:
            raise SplunkConnectionError("No Splunk configuration found")

        # Decrypt secrets
        auth_token = None
        auth_password = None

        if config.auth_type == "token" and config.auth_token_encrypted:
            auth_token = decrypt_secret(config.auth_token_encrypted)
        elif config.auth_type == "basic" and config.auth_password_encrypted:
            auth_password = decrypt_secret(config.auth_password_encrypted)

        return cls(
            base_url=config.base_url,
            auth_type=config.auth_type,
            auth_token=auth_token,
            auth_username=config.auth_username,
            auth_password=auth_password,
            verify_tls=config.verify_tls,
            es_app_namespace=config.es_app_namespace,
            es_owner=config.es_owner,
        )

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        if self.auth_type == "token" and self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        return headers

    def _get_auth(self) -> Optional[Tuple[str, str]]:
        """Get basic auth tuple if using basic auth."""
        if self.auth_type == "basic" and self.auth_username and self.auth_password:
            return (self.auth_username, self.auth_password)
        return None

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Make authenticated request to Splunk API.

        Args:
            method: HTTP method
            endpoint: API endpoint (relative to base_url)
            params: Query parameters
            data: Request body (for POST)

        Returns:
            JSON response

        Raises:
            SplunkAuthError: Authentication failed
            SplunkConnectionError: Connection failed
            SplunkConnectorError: Other API errors
        """
        url = urljoin(self.base_url, endpoint)

        # Add output_mode=json to all requests
        params = params or {}
        params["output_mode"] = "json"

        try:
            async with httpx.AsyncClient(
                verify=self.verify_tls,
                timeout=self.timeout,
            ) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=self._get_headers(),
                    auth=self._get_auth(),
                    params=params,
                    data=data,
                )

                if response.status_code == 401:
                    raise SplunkAuthError("Authentication failed")

                if response.status_code == 403:
                    raise SplunkAuthError("Access forbidden - check permissions")

                if response.status_code >= 400:
                    raise SplunkConnectorError(
                        f"Splunk API error: {response.status_code} - {response.text}"
                    )

                return response.json()

        except httpx.ConnectError as e:
            raise SplunkConnectionError(f"Failed to connect to Splunk: {e}")
        except httpx.TimeoutException as e:
            raise SplunkConnectionError(f"Connection timeout: {e}")
        except json.JSONDecodeError as e:
            raise SplunkConnectorError(f"Invalid JSON response: {e}")

    async def test_connection(self) -> Dict[str, Any]:
        """
        Test connection to Splunk server.

        Returns:
            Server info dict with version, build, etc.

        Raises:
            SplunkConnectionError: Connection failed
            SplunkAuthError: Authentication failed
        """
        response = await self._request("GET", "/services/server/info")

        # Extract server info from response
        entry = response.get("entry", [{}])[0]
        content = entry.get("content", {})

        return {
            "version": content.get("version", "unknown"),
            "build": content.get("build", "unknown"),
            "server_name": content.get("serverName", "unknown"),
            "os_name": content.get("os_name", "unknown"),
            "license_state": content.get("licenseState", "unknown"),
        }

    async def get_es_correlation_searches(self) -> List[Dict[str, Any]]:
        """
        Fetch all ES correlation searches (saved searches with correlation action).

        Returns:
            List of correlation search definitions
        """
        # ES correlation searches are saved searches in the ES app namespace
        endpoint = f"/servicesNS/{self.es_owner}/{self.es_app_namespace}/saved/searches"

        params = {
            "search": "action.correlationsearch.enabled=1",  # Filter to correlation searches
            "count": 0,  # Return all
        }

        response = await self._request("GET", endpoint, params=params)

        searches = []
        for entry in response.get("entry", []):
            content = entry.get("content", {})

            # Extract MITRE tags if present
            mitre_tags = []
            annotations = content.get("action.correlationsearch.annotations", "")
            if annotations:
                try:
                    ann_data = json.loads(annotations)
                    mitre_tags = ann_data.get("mitre_attack", [])
                except json.JSONDecodeError:
                    pass

            searches.append({
                "savedsearch_id": entry.get("name"),
                "name": content.get("action.correlationsearch.label", entry.get("name")),
                "description": content.get("description", ""),
                "spl": content.get("search", ""),
                "severity": self._map_severity(content.get("alert.severity", "3")),
                "enabled": content.get("disabled", "0") == "0",
                "app": entry.get("acl", {}).get("app", self.es_app_namespace),
                "owner": entry.get("acl", {}).get("owner", self.es_owner),
                "mitre_tags": mitre_tags,
                "raw_payload": content,  # Full content for debugging
            })

        return searches

    def _map_severity(self, splunk_severity: str) -> str:
        """Map Splunk numeric severity to standard severity string."""
        severity_map = {
            "1": "low",
            "2": "low",
            "3": "medium",
            "4": "high",
            "5": "critical",
        }
        return severity_map.get(str(splunk_severity), "medium")

    async def search_oneshot(
        self,
        spl: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        max_results: int = 10000,
    ) -> List[Dict[str, Any]]:
        """
        Execute a one-shot search and return results.

        Args:
            spl: SPL query
            earliest_time: Search time range start
            latest_time: Search time range end
            max_results: Maximum number of results

        Returns:
            List of result dictionaries
        """
        endpoint = "/services/search/jobs/oneshot"

        data = {
            "search": spl if spl.startswith("search ") or spl.startswith("|") else f"search {spl}",
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "max_count": max_results,
            "output_mode": "json",
        }

        response = await self._request("POST", endpoint, data=data)
        return response.get("results", [])

    async def get_soar_playbook_runs(
        self,
        index: str = "phantom_playbook_run",
        days: int = 30,
        max_results: int = 10000,
    ) -> List[Dict[str, Any]]:
        """
        Fetch SOAR playbook execution logs from Splunk index.

        Args:
            index: Splunk index containing playbook runs
            days: Number of days to look back
            max_results: Maximum results to return

        Returns:
            List of playbook run events
        """
        spl = f'index="{index}" | head {max_results}'
        earliest = f"-{days}d"

        results = await self.search_oneshot(
            spl=spl,
            earliest_time=earliest,
            latest_time="now",
            max_results=max_results,
        )

        # Parse and normalize results
        runs = []
        for event in results:
            run = {
                "playbook_run_id": event.get("playbook_run_id", event.get("_cd")),
                "playbook_name": event.get("playbook_name", event.get("playbook")),
                "playbook_id": event.get("playbook_id"),
                "status": event.get("status", "unknown"),
                "start_time": self._parse_time(event.get("start_time")),
                "end_time": self._parse_time(event.get("end_time")),
                "duration_seconds": self._parse_float(event.get("duration")),
                "container_id": event.get("container_id", event.get("container")),
                "event_time": self._parse_time(event.get("_time")),
                "index_time": self._parse_time(event.get("_indextime")),
                "raw_event": json.dumps(event),
            }
            runs.append(run)

        return runs

    async def get_soar_action_runs(
        self,
        index: str = "phantom_action_run",
        days: int = 30,
        max_results: int = 50000,
    ) -> List[Dict[str, Any]]:
        """
        Fetch SOAR action execution logs from Splunk index.

        Args:
            index: Splunk index containing action runs
            days: Number of days to look back
            max_results: Maximum results to return

        Returns:
            List of action run events
        """
        spl = f'index="{index}" | head {max_results}'
        earliest = f"-{days}d"

        results = await self.search_oneshot(
            spl=spl,
            earliest_time=earliest,
            latest_time="now",
            max_results=max_results,
        )

        # Parse and normalize results
        actions = []
        for event in results:
            action = {
                "action_run_id": event.get("action_run_id", event.get("_cd")),
                "playbook_run_id": event.get("playbook_run_id"),
                "action_name": event.get("action", event.get("action_name", "unknown")),
                "app_name": event.get("app", event.get("app_name")),
                "status": event.get("status", "unknown"),
                "duration_seconds": self._parse_float(event.get("duration")),
                "error_message": event.get("message") if event.get("status") == "failure" else None,
                "event_time": self._parse_time(event.get("_time")),
                "index_time": self._parse_time(event.get("_indextime")),
                "raw_event": json.dumps(event),
            }
            actions.append(action)

        return actions

    def _parse_time(self, value: Any) -> Optional[datetime]:
        """Parse various time formats to datetime."""
        if not value:
            return None

        if isinstance(value, datetime):
            return value

        if isinstance(value, (int, float)):
            # Unix timestamp
            return datetime.fromtimestamp(value)

        if isinstance(value, str):
            # Try common formats
            for fmt in [
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
            ]:
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue

            # Try parsing as epoch
            try:
                return datetime.fromtimestamp(float(value))
            except (ValueError, TypeError):
                pass

        return None

    def _parse_float(self, value: Any) -> Optional[float]:
        """Parse value to float."""
        if value is None:
            return None
        try:
            return float(value)
        except (ValueError, TypeError):
            return None


async def get_active_splunk_config(db: AsyncSession) -> Optional[SplunkConfig]:
    """Get the active Splunk configuration."""
    stmt = select(SplunkConfig).where(SplunkConfig.is_active == True)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()
