module github.com/apigee/apigee-remote-service-cli

go 1.13

replace github.com/apigee/apigee-remote-service-golib => github.com/theganyo/apigee-remote-service-golib v0.0.0-20200417215038-eb2754109270

replace github.com/apigee/apigee-remote-service-envoy => github.com/theganyo/apigee-remote-service-envoy v0.0.2-dev.0.20200420171643-2bad5a8de6d9

// replace github.com/apigee/apigee-remote-service-golib => ../apigee-remote-service-golib

// replace github.com/apigee/apigee-remote-service-envoy => ../apigee-remote-service-envoy

replace github.com/apigee/apigee-remote-service-cli => ./

require (
	github.com/apigee/apigee-remote-service-envoy v0.0.0-00000000000000-000000000000
	github.com/apigee/apigee-remote-service-golib v0.0.0-00010101000000-000000000000
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d
	github.com/google/go-querystring v1.0.0
	github.com/lestrrat-go/jwx v0.9.1
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.0.0
	go.uber.org/multierr v1.5.0
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c
)
