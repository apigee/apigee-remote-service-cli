module github.com/apigee/apigee-remote-service-cli

go 1.15

// replace github.com/apigee/apigee-remote-service-golib => ../apigee-remote-service-golib

// replace github.com/apigee/apigee-remote-service-envoy => ../apigee-remote-service-envoy

require (
	github.com/apigee/apigee-remote-service-envoy v1.3.0-rc.1
	github.com/apigee/apigee-remote-service-golib v1.3.0-rc.1
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d
	github.com/lestrrat-go/jwx v1.0.5
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.1.1
	go.uber.org/multierr v1.6.0
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776
)
