"""REST client for Pentaho Data Integration (PDI).

PDI exposes a REST API through its Carte server (and through the Pentaho/DI
Server under the ``/pentaho`` context). This module wraps the most useful
``/kettle/*`` endpoints so you can connect to PDI, run transformations and
jobs, and monitor them from Python.

Typical usage::

    from pdi_client import PDIClient

    client = PDIClient("http://localhost:8081", "cluster", "cluster")
    print(client.get_server_status()["status"])

    run_id = client.run_transformation_file("/data/etl/load_sales.ktr")
    result = client.wait_for_transformation("load_sales", carte_id=run_id)
    print(result["status"], result["error"])
"""

import base64
import gzip
import time
import xml.etree.ElementTree as ET

import requests

VALID_LOG_LEVELS = ("Nothing", "Error", "Minimal", "Basic", "Detailed", "Debug", "Rowlevel")

# Status descriptions after which a transformation/job will not progress further.
_TERMINAL_STATUS_PREFIXES = ("finished", "stopped", "halted")


class PDIError(Exception):
    """Base error for all PDI client failures."""


class PDIConnectionError(PDIError):
    """Raised when the PDI server cannot be reached at all."""


class PDIRequestError(PDIError):
    """Raised when the PDI server rejects or fails a request."""


def _text(element, tag, default=""):
    value = element.findtext(tag)
    return default if value is None else value.strip()


def _int(element, tag, default=0):
    try:
        return int(_text(element, tag))
    except ValueError:
        return default


def _float(element, tag, default=0.0):
    try:
        return float(_text(element, tag))
    except ValueError:
        return default


def _decode_carte_log(encoded):
    """Decode a Carte ``logging_string`` payload (base64-encoded gzip text)."""
    if not encoded:
        return ""
    try:
        return gzip.decompress(base64.b64decode(encoded)).decode("utf-8", errors="replace")
    except (ValueError, OSError):
        # Some server versions return the log as plain text.
        return encoded


def _is_terminal_status(status_desc):
    status = status_desc.lower()
    return any(status.startswith(prefix) for prefix in _TERMINAL_STATUS_PREFIXES)


class PDIClient:
    """Client for the PDI (Kettle) REST API served by Carte or the DI Server.

    :param base_url: Server root, e.g. ``http://localhost:8081`` for Carte or
        ``http://localhost:8080/pentaho`` for the Pentaho/DI Server.
    :param username: HTTP Basic auth user (Carte default: ``cluster``).
    :param password: HTTP Basic auth password (Carte default: ``cluster``).
    :param timeout: Per-request timeout in seconds.
    :param verify_ssl: Set to False only for servers with self-signed certs.
    """

    def __init__(self, base_url, username="cluster", password="cluster",
                 timeout=30, verify_ssl=True):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()
        self._session.auth = (username, password)
        self._session.verify = verify_ssl

    # ------------------------------------------------------------------ #
    # Low-level plumbing
    # ------------------------------------------------------------------ #

    def _get(self, path, params=None):
        url = f"{self.base_url}{path}"
        try:
            response = self._session.get(url, params=params, timeout=self.timeout)
        except requests.exceptions.RequestException as exc:
            raise PDIConnectionError(
                f"Could not reach PDI server at {self.base_url}: {exc}"
            ) from exc

        if response.status_code == 401:
            raise PDIRequestError(
                "PDI server rejected the credentials (HTTP 401). "
                "Check username/password (Carte default is cluster/cluster)."
            )
        if response.status_code >= 400:
            detail = self._webresult_message(response.text)
            raise PDIRequestError(
                f"PDI server returned HTTP {response.status_code} for {path}"
                + (f": {detail}" if detail else "")
            )
        return response.text

    @staticmethod
    def _parse_xml(text):
        try:
            return ET.fromstring(text)
        except ET.ParseError as exc:
            raise PDIRequestError(
                f"PDI server returned a response that is not valid XML: {exc}"
            ) from exc

    @staticmethod
    def _webresult_message(text):
        """Best-effort extraction of the <message> from a webresult payload."""
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return ""
        if root.tag != "webresult":
            return ""
        return _text(root, "message")

    def _parse_webresult(self, text):
        root = self._parse_xml(text)
        if root.tag != "webresult":
            raise PDIRequestError(f"Expected a <webresult> response, got <{root.tag}>")
        result = {
            "result": _text(root, "result"),
            "message": _text(root, "message"),
            "id": _text(root, "id"),
        }
        if result["result"].upper() != "OK":
            raise PDIRequestError(f"PDI request failed: {result['message'] or 'unknown error'}")
        return result

    # ------------------------------------------------------------------ #
    # Server status
    # ------------------------------------------------------------------ #

    def check_connection(self):
        """Return True if the server answers ``/kettle/status/``; raise otherwise."""
        self.get_server_status()
        return True

    def get_server_status(self):
        """Return the server status plus every registered transformation and job."""
        root = self._parse_xml(self._get("/kettle/status/", params={"xml": "Y"}))
        transformations = [
            {
                "name": _text(status, "transname"),
                "id": _text(status, "id"),
                "status": _text(status, "status_desc"),
            }
            for status in root.iter("transstatus")
        ]
        jobs = [
            {
                "name": _text(status, "jobname"),
                "id": _text(status, "id"),
                "status": _text(status, "status_desc"),
            }
            for status in root.iter("jobstatus")
        ]
        return {
            "status": _text(root, "statusdesc"),
            "memory_free": _int(root, "memory_free"),
            "memory_total": _int(root, "memory_total"),
            "cpu_cores": _int(root, "cpu_cores"),
            "uptime": _int(root, "uptime"),
            "load_average": _float(root, "load_avg"),
            "os_name": _text(root, "os_name"),
            "transformations": transformations,
            "jobs": jobs,
        }

    # ------------------------------------------------------------------ #
    # Transformations
    # ------------------------------------------------------------------ #

    def run_transformation_file(self, ktr_path, log_level="Basic", params=None):
        """Execute a ``.ktr`` file that is accessible from the PDI server.

        Extra ``params`` are passed to the transformation as named parameters.
        Returns the Carte object id of the running transformation.
        """
        query = self._execution_query({"trans": ktr_path}, log_level, params)
        return self._parse_webresult(self._get("/kettle/executeTrans/", params=query))["id"]

    def get_transformation_status(self, name, carte_id=None, with_log=False):
        """Return the status of a transformation, including per-step metrics."""
        params = {"name": name, "xml": "Y"}
        if carte_id:
            params["id"] = carte_id
        root = self._parse_xml(self._get("/kettle/transStatus/", params=params))
        if root.tag == "webresult":
            self._parse_webresult(ET.tostring(root, encoding="unicode"))
        steps = [
            {
                "name": _text(step, "stepname"),
                "copy": _int(step, "copy"),
                "lines_read": _int(step, "linesRead"),
                "lines_written": _int(step, "linesWritten"),
                "lines_input": _int(step, "linesInput"),
                "lines_output": _int(step, "linesOutput"),
                "errors": _int(step, "errors"),
                "status": _text(step, "statusDescription"),
                "seconds": _float(step, "seconds"),
                "speed": _text(step, "speed"),
            }
            for step in root.iter("stepstatus")
        ]
        status = {
            "name": _text(root, "transname"),
            "id": _text(root, "id"),
            "status": _text(root, "status_desc"),
            "error": _text(root, "error_desc"),
            "paused": _text(root, "paused") == "Y",
            "steps": steps,
        }
        if with_log:
            status["log"] = _decode_carte_log(_text(root, "logging_string"))
        return status

    def start_transformation(self, name, carte_id=None):
        """Start a transformation already registered on the server."""
        return self._trans_command("/kettle/startTrans/", name, carte_id)

    def pause_transformation(self, name, carte_id=None):
        """Pause a running transformation (calling again resumes it)."""
        return self._trans_command("/kettle/pauseTrans/", name, carte_id)

    def stop_transformation(self, name, carte_id=None):
        """Stop a running transformation."""
        return self._trans_command("/kettle/stopTrans/", name, carte_id)

    def remove_transformation(self, name, carte_id=None):
        """Remove a finished transformation from the server's list."""
        return self._trans_command("/kettle/removeTrans/", name, carte_id)

    def wait_for_transformation(self, name, carte_id=None, poll_interval=2,
                                timeout=300, with_log=False):
        """Poll until the transformation reaches a terminal status.

        Returns the final status dict. Raises :class:`PDIError` on timeout.
        """
        return self._wait(self.get_transformation_status, name, carte_id,
                          poll_interval, timeout, with_log)

    # ------------------------------------------------------------------ #
    # Jobs
    # ------------------------------------------------------------------ #

    def run_job_file(self, kjb_path, log_level="Basic", params=None):
        """Execute a ``.kjb`` file that is accessible from the PDI server."""
        query = self._execution_query({"job": kjb_path}, log_level, params)
        return self._parse_webresult(self._get("/kettle/executeJob/", params=query))["id"]

    def get_job_status(self, name, carte_id=None, with_log=False):
        """Return the status of a job."""
        params = {"name": name, "xml": "Y"}
        if carte_id:
            params["id"] = carte_id
        root = self._parse_xml(self._get("/kettle/jobStatus/", params=params))
        if root.tag == "webresult":
            self._parse_webresult(ET.tostring(root, encoding="unicode"))
        status = {
            "name": _text(root, "jobname"),
            "id": _text(root, "id"),
            "status": _text(root, "status_desc"),
            "error": _text(root, "error_desc"),
        }
        if with_log:
            status["log"] = _decode_carte_log(_text(root, "logging_string"))
        return status

    def start_job(self, name, carte_id=None):
        """Start a job already registered on the server."""
        return self._job_command("/kettle/startJob/", name, carte_id)

    def stop_job(self, name, carte_id=None):
        """Stop a running job."""
        return self._job_command("/kettle/stopJob/", name, carte_id)

    def remove_job(self, name, carte_id=None):
        """Remove a finished job from the server's list."""
        return self._job_command("/kettle/removeJob/", name, carte_id)

    def wait_for_job(self, name, carte_id=None, poll_interval=2,
                     timeout=300, with_log=False):
        """Poll until the job reaches a terminal status."""
        return self._wait(self.get_job_status, name, carte_id,
                          poll_interval, timeout, with_log)

    # ------------------------------------------------------------------ #
    # Shared helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _execution_query(target, log_level, params):
        if log_level not in VALID_LOG_LEVELS:
            raise ValueError(f"log_level must be one of {VALID_LOG_LEVELS}, got {log_level!r}")
        query = dict(target)
        query["level"] = log_level
        for reserved in query:
            if params and reserved in params:
                raise ValueError(f"{reserved!r} is a reserved query parameter")
        if params:
            query.update(params)
        return query

    def _trans_command(self, path, name, carte_id):
        params = {"name": name, "xml": "Y"}
        if carte_id:
            params["id"] = carte_id
        return self._parse_webresult(self._get(path, params=params))

    def _job_command(self, path, name, carte_id):
        params = {"name": name, "xml": "Y"}
        if carte_id:
            params["id"] = carte_id
        return self._parse_webresult(self._get(path, params=params))

    @staticmethod
    def _wait(get_status, name, carte_id, poll_interval, timeout, with_log):
        deadline = time.monotonic() + timeout
        while True:
            status = get_status(name, carte_id=carte_id, with_log=with_log)
            if _is_terminal_status(status["status"]):
                return status
            if time.monotonic() >= deadline:
                raise PDIError(
                    f"Timed out after {timeout}s waiting for {name!r} "
                    f"(last status: {status['status']})"
                )
            time.sleep(poll_interval)
