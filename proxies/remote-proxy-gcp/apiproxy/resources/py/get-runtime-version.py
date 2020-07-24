import os

version = os.environ.get("APIGEE_DPCOLOR", "")

if len(version) > 0:
    flow.setVariable("runtime_version", ".".join(version[1:4]))
else:
    flow.setVariable("runtime_version", "unknown")
