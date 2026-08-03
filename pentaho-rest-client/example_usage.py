"""Connect to a Pentaho Data Integration (PDI) server using its REST API.

Configure the connection through environment variables:

    PDI_BASE_URL    Server root (default: http://localhost:8081 for Carte).
                    For the Pentaho/DI Server use http://<host>:8080/pentaho
    PDI_USERNAME    Basic auth user (default: cluster)
    PDI_PASSWORD    Basic auth password (default: cluster)
    PDI_TRANS_PATH  Optional path to a .ktr file on the server to execute

Run with:  python example_usage.py
"""

import os
import sys

from pdi_client import PDIClient, PDIError


def main():
    base_url = os.environ.get("PDI_BASE_URL", "http://localhost:8081")
    username = os.environ.get("PDI_USERNAME", "cluster")
    password = os.environ.get("PDI_PASSWORD", "cluster")

    client = PDIClient(base_url, username, password)

    print(f"Connecting to PDI at {base_url} ...")
    status = client.get_server_status()
    print(f"Server status : {status['status']}")
    print(f"Operating sys : {status['os_name']}")
    print(f"CPU cores     : {status['cpu_cores']}")
    print(f"Memory        : {status['memory_free']:,} free / {status['memory_total']:,} total")

    if status["transformations"]:
        print("\nTransformations on the server:")
        for trans in status["transformations"]:
            print(f"  - {trans['name']} [{trans['status']}]")
    if status["jobs"]:
        print("\nJobs on the server:")
        for job in status["jobs"]:
            print(f"  - {job['name']} [{job['status']}]")

    ktr_path = os.environ.get("PDI_TRANS_PATH")
    if not ktr_path:
        print("\nSet PDI_TRANS_PATH to a .ktr file on the server to execute it.")
        return

    trans_name = os.path.splitext(os.path.basename(ktr_path))[0]
    print(f"\nExecuting transformation {ktr_path} ...")
    run_id = client.run_transformation_file(ktr_path)
    print(f"Started with id {run_id}, waiting for it to finish ...")

    result = client.wait_for_transformation(trans_name, carte_id=run_id, with_log=True)
    print(f"Final status: {result['status']}")
    if result["error"]:
        print(f"Error: {result['error']}")
    for step in result["steps"]:
        print(f"  step {step['name']}: {step['lines_written']} lines written, "
              f"{step['errors']} errors ({step['status']})")


if __name__ == "__main__":
    try:
        main()
    except PDIError as exc:
        print(f"\nPDI error: {exc}", file=sys.stderr)
        sys.exit(1)
