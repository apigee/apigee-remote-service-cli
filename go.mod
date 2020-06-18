module github.com/apigee/apigee-remote-service-cli

go 1.13

// replace github.com/apigee/apigee-remote-service-golib => ../apigee-remote-service-golib

// replace github.com/apigee/apigee-remote-service-envoy => ../apigee-remote-service-envoy

require (
	github.com/apigee/apigee-remote-service-envoy v1.0.0-beta.3.0.20200618203739-37ac2b14898d
	github.com/apigee/apigee-remote-service-golib v1.0.0-beta.3.0.20200618203547-765ca9c46796
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d
	github.com/google/go-querystring v1.0.0
	github.com/lestrrat-go/jwx v1.0.2
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.0.0
	go.uber.org/multierr v1.5.0
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776
)
