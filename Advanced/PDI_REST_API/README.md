# Connect to Pentaho Data Integration (PDI) using REST

PDI (Kettle) ships with a lightweight web server called **Carte** that exposes a
REST API for running and monitoring transformations (`.ktr`) and jobs (`.kjb`).
The same API is also available on the **Pentaho/DI Server** under the `/pentaho`
context. `pdi_client.py` in this folder is a small Python client for that API.

## 1. Start the PDI server

On the machine where PDI is installed:

```bash
# Carte, listening on port 8081 (default credentials: cluster / cluster)
./carte.sh localhost 8081        # Linux / macOS
Carte.bat localhost 8081         # Windows
```

Verify it is up by opening `http://localhost:8081/kettle/status/` in a browser
(log in with `cluster` / `cluster`).

If you use the full Pentaho/DI Server instead, the base URL is
`http://<host>:8080/pentaho` and you authenticate with your Pentaho user
(e.g. `admin`).

## 2. Install the Python dependency

```bash
pip install -r requirements.txt
```

## 3. Connect from Python

```python
from pdi_client import PDIClient

client = PDIClient(
    "http://localhost:8081",   # or "http://myserver:8080/pentaho" for DI Server
    username="cluster",
    password="cluster",
)

# Check the connection and inspect the server
status = client.get_server_status()
print(status["status"])            # "Online"
print(status["transformations"])   # everything registered on the server

# Run a .ktr file that the *server* can see, with named parameters
run_id = client.run_transformation_file(
    "/data/etl/load_sales.ktr",
    log_level="Basic",
    params={"REGION": "emea"},
)

# Block until it finishes and inspect the result
result = client.wait_for_transformation("load_sales", carte_id=run_id, with_log=True)
print(result["status"])            # "Finished"
for step in result["steps"]:
    print(step["name"], step["lines_written"], step["errors"])
print(result["log"])               # full Kettle log (decoded for you)
```

Jobs work the same way: `run_job_file`, `get_job_status`, `wait_for_job`,
`stop_job`, `remove_job`.

You can also try it from the command line:

```bash
export PDI_BASE_URL=http://localhost:8081
export PDI_USERNAME=cluster
export PDI_PASSWORD=cluster
export PDI_TRANS_PATH=/data/etl/load_sales.ktr   # optional
python example_usage.py
```

## What the client covers

| Method | PDI endpoint | Purpose |
|---|---|---|
| `get_server_status()` | `GET /kettle/status/` | Server health + registered trans/jobs |
| `run_transformation_file(path)` | `GET /kettle/executeTrans/` | Execute a `.ktr` file |
| `get_transformation_status(name)` | `GET /kettle/transStatus/` | Status, step metrics, log |
| `start_transformation(name)` | `GET /kettle/startTrans/` | Start a registered transformation |
| `pause_transformation(name)` | `GET /kettle/pauseTrans/` | Pause / resume |
| `stop_transformation(name)` | `GET /kettle/stopTrans/` | Stop |
| `remove_transformation(name)` | `GET /kettle/removeTrans/` | Remove from the server list |
| `wait_for_transformation(name)` | (polls `transStatus`) | Block until finished |
| `run_job_file(path)` | `GET /kettle/executeJob/` | Execute a `.kjb` file |
| `get_job_status(name)` | `GET /kettle/jobStatus/` | Job status + log |
| `start_job` / `stop_job` / `remove_job` | `GET /kettle/startJob/` … | Job lifecycle |
| `wait_for_job(name)` | (polls `jobStatus`) | Block until finished |

Notes that save debugging time:

- **File paths are resolved on the server**, not on the machine running Python.
  `executeTrans` needs a path the Carte/DI Server process can read.
- Carte identifies each run by **name + id** — pass the `carte_id` returned by
  `run_transformation_file` when several runs share a name.
- The `logging_string` in status responses is base64-encoded gzip; the client
  decodes it automatically when you pass `with_log=True`.
- Valid log levels: `Nothing`, `Error`, `Minimal`, `Basic`, `Detailed`,
  `Debug`, `Rowlevel`.
- Carte uses HTTP **Basic auth** (defaults `cluster`/`cluster`, configurable in
  `pwd/kettle.pwd`). Use HTTPS and real credentials for anything non-local.

## Run the tests

The tests mock the HTTP layer, so no PDI server is required:

```bash
python -m pytest test_pdi_client.py -v
```
