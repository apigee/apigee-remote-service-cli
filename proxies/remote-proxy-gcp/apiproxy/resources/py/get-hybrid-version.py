import os

version = os.environ.get("APIGEE_DPCOLOR", "unknown")

flow.setVariable("hybrid_version", version)