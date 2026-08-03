"""Tests for pdi_client using mocked HTTP responses (no PDI server needed).

Run with:  python -m pytest test_pdi_client.py -v
"""

import base64
import gzip
from unittest.mock import MagicMock

import pytest

from pdi_client import PDIClient, PDIConnectionError, PDIRequestError, PDIError

SERVER_STATUS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<serverstatus>
  <statusdesc>Online</statusdesc>
  <memory_free>209715200</memory_free>
  <memory_total>536870912</memory_total>
  <cpu_cores>8</cpu_cores>
  <cpu_process_time>1234</cpu_process_time>
  <uptime>86400000</uptime>
  <thread_count>25</thread_count>
  <load_avg>0.5</load_avg>
  <os_name>Linux</os_name>
  <os_version>6.1</os_version>
  <os_arch>amd64</os_arch>
  <transstatuslist>
    <transstatus>
      <transname>load_sales</transname>
      <id>abc-123</id>
      <status_desc>Finished</status_desc>
    </transstatus>
  </transstatuslist>
  <jobstatuslist>
    <jobstatus>
      <jobname>nightly_etl</jobname>
      <id>def-456</id>
      <status_desc>Running</status_desc>
    </jobstatus>
  </jobstatuslist>
</serverstatus>"""

WEBRESULT_OK_XML = """<?xml version="1.0" encoding="UTF-8"?>
<webresult>
  <result>OK</result>
  <message>Transformation started</message>
  <id>abc-123</id>
</webresult>"""

WEBRESULT_ERROR_XML = """<?xml version="1.0" encoding="UTF-8"?>
<webresult>
  <result>ERROR</result>
  <message>Unable to find transformation</message>
  <id/>
</webresult>"""


def encoded_log(text):
    return base64.b64encode(gzip.compress(text.encode("utf-8"))).decode("ascii")


def trans_status_xml(status_desc, log=""):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<transstatus>
  <transname>load_sales</transname>
  <id>abc-123</id>
  <status_desc>{status_desc}</status_desc>
  <error_desc/>
  <paused>N</paused>
  <stepstatuslist>
    <stepstatus>
      <stepname>Table output</stepname>
      <copy>0</copy>
      <linesRead>100</linesRead>
      <linesWritten>100</linesWritten>
      <linesInput>0</linesInput>
      <linesOutput>0</linesOutput>
      <errors>0</errors>
      <statusDescription>Finished</statusDescription>
      <seconds>1.5</seconds>
      <speed>66</speed>
    </stepstatus>
  </stepstatuslist>
  <logging_string><![CDATA[{encoded_log(log) if log else ""}]]></logging_string>
</transstatus>"""


def make_response(text, status_code=200):
    response = MagicMock()
    response.status_code = status_code
    response.text = text
    return response


def make_client(*responses):
    client = PDIClient("http://localhost:8081", "cluster", "cluster")
    client._session = MagicMock()
    client._session.get.side_effect = list(responses)
    return client


def test_get_server_status_parses_server_and_registered_objects():
    client = make_client(make_response(SERVER_STATUS_XML))
    status = client.get_server_status()

    assert status["status"] == "Online"
    assert status["cpu_cores"] == 8
    assert status["memory_total"] == 536870912
    assert status["transformations"] == [
        {"name": "load_sales", "id": "abc-123", "status": "Finished"}
    ]
    assert status["jobs"] == [
        {"name": "nightly_etl", "id": "def-456", "status": "Running"}
    ]

    url = client._session.get.call_args.args[0]
    assert url == "http://localhost:8081/kettle/status/"


def test_check_connection_ok():
    client = make_client(make_response(SERVER_STATUS_XML))
    assert client.check_connection() is True


def test_connection_error_is_wrapped():
    import requests

    client = make_client()
    client._session.get.side_effect = requests.exceptions.ConnectionError("refused")
    with pytest.raises(PDIConnectionError, match="Could not reach PDI server"):
        client.check_connection()


def test_bad_credentials_raise_helpful_error():
    client = make_client(make_response("", status_code=401))
    with pytest.raises(PDIRequestError, match="HTTP 401"):
        client.get_server_status()


def test_run_transformation_file_returns_carte_id():
    client = make_client(make_response(WEBRESULT_OK_XML))
    run_id = client.run_transformation_file(
        "/data/etl/load_sales.ktr", params={"REGION": "emea"}
    )

    assert run_id == "abc-123"
    kwargs = client._session.get.call_args.kwargs
    assert kwargs["params"]["trans"] == "/data/etl/load_sales.ktr"
    assert kwargs["params"]["level"] == "Basic"
    assert kwargs["params"]["REGION"] == "emea"


def test_run_transformation_rejects_reserved_param_names():
    client = make_client()
    with pytest.raises(ValueError, match="reserved"):
        client.run_transformation_file("/a.ktr", params={"trans": "x"})


def test_run_transformation_rejects_bad_log_level():
    client = make_client()
    with pytest.raises(ValueError, match="log_level"):
        client.run_transformation_file("/a.ktr", log_level="Verbose")


def test_webresult_error_raises():
    client = make_client(make_response(WEBRESULT_ERROR_XML))
    with pytest.raises(PDIRequestError, match="Unable to find transformation"):
        client.run_transformation_file("/missing.ktr")


def test_get_transformation_status_parses_steps_and_log():
    xml = trans_status_xml("Finished", log="2026/08/03 - load_sales - Dispatching started")
    client = make_client(make_response(xml))
    status = client.get_transformation_status("load_sales", carte_id="abc-123", with_log=True)

    assert status["status"] == "Finished"
    assert status["paused"] is False
    assert status["steps"][0]["name"] == "Table output"
    assert status["steps"][0]["lines_written"] == 100
    assert "Dispatching started" in status["log"]

    kwargs = client._session.get.call_args.kwargs
    assert kwargs["params"] == {"name": "load_sales", "xml": "Y", "id": "abc-123"}


def test_wait_for_transformation_polls_until_finished():
    client = make_client(
        make_response(trans_status_xml("Running")),
        make_response(trans_status_xml("Finished")),
    )
    result = client.wait_for_transformation("load_sales", poll_interval=0, timeout=5)

    assert result["status"] == "Finished"
    assert client._session.get.call_count == 2


def test_wait_for_transformation_times_out():
    client = PDIClient("http://localhost:8081")
    client._session = MagicMock()
    client._session.get.return_value = make_response(trans_status_xml("Running"))

    with pytest.raises(PDIError, match="Timed out"):
        client.wait_for_transformation("load_sales", poll_interval=0, timeout=0)


def test_job_lifecycle_commands():
    client = make_client(
        make_response(WEBRESULT_OK_XML),
        make_response(WEBRESULT_OK_XML),
    )
    run_id = client.run_job_file("/data/etl/nightly.kjb")
    assert run_id == "abc-123"

    stop = client.stop_job("nightly", carte_id="def-456")
    assert stop["result"] == "OK"
    kwargs = client._session.get.call_args.kwargs
    assert kwargs["params"] == {"name": "nightly", "xml": "Y", "id": "def-456"}
