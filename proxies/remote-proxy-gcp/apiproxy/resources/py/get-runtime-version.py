import os

version = os.environ.get("APIGEE_DPCOLOR", "unknown")

flow.setVariable("runtime_version", version)