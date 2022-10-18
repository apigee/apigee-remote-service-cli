module github.com/apigee/apigee-remote-service-cli/v2

go 1.16

// replace github.com/apigee/apigee-remote-service-golib/v2 => ../apigee-remote-service-golib

// replace github.com/apigee/apigee-remote-service-envoy/v2 => ../apigee-remote-service-envoy

require (
	github.com/apigee/apigee-remote-service-envoy/v2 v2.0.6
	github.com/apigee/apigee-remote-service-golib/v2 v2.0.6
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d
	github.com/lestrrat-go/jwx v1.1.6
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.1.3
	gopkg.in/yaml.v3 v3.0.1
)
