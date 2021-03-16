module github.com/apigee/apigee-remote-service-cli

go 1.16

// replace github.com/apigee/apigee-remote-service-golib => ../apigee-remote-service-golib

// replace github.com/apigee/apigee-remote-service-envoy => ../apigee-remote-service-envoy

require (
	github.com/apigee/apigee-remote-service-envoy v1.4.3-0.20210316230715-0e7a3f049b93
	github.com/apigee/apigee-remote-service-golib v1.4.1-0.20210316222324-5cae521e6214
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d
	github.com/lestrrat-go/jwx v1.1.5
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.1.3
	go.uber.org/multierr v1.6.0
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)
