# edgemicro-internal

An Apigee Edge proxy to support analytics and quota. 

## Development

IMPORTANT: If you change any proxies, you must:
1. update the returned version(s) in the Send-Version.xml of the affected proxies.
2. run `bin/build_proxies.sh` to generate proxies.go.
3. rebuild `apigee-remote-service-cli` to include it for provisioning.
