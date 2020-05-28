# edgemicro-internal

An Apigee Edge proxy to support analytics and quota. 

## Development

The legacy proxy `default.xml` file contains <VirtualHost/> entries. When processing, 
the provision cmd assumes that it will have one <VirtualHost>default</VirtualHost> and 
may have zero or more <VirtualHost>secure</VirtualHost> entries. Adjust to match before 
running the `build_proxies.sh` as necessary.

IMPORTANT: If you change any proxies, you must:
1. update the returned version(s) in the Send-Version.xml of the affected proxies.
2. run `bin/build_proxies.sh` to generate proxies.go.
3. rebuild `apigee-remote-service-cli` to include it for provisioning.
