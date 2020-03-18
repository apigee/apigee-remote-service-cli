module github.com/apigee/apigee-remote-service-cli

go 1.13

replace github.com/apigee/apigee-remote-service-golib => github.com/theganyo/apigee-remote-service-golib v0.0.0-20200318193336-89e7c077d23b

// replace github.com/apigee/apigee-remote-service-golib => ../apigee-remote-service-golib

replace github.com/apigee/apigee-remote-service-cli => ./

require (
	github.com/apigee/apigee-remote-service-golib v0.0.0-00010101000000-000000000000
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d
	github.com/google/go-querystring v1.0.0
	github.com/lestrrat/go-jwx v0.0.0-20180221005942-b7d4802280ae
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v0.0.6
	go.uber.org/multierr v1.4.0
	gopkg.in/yaml.v2 v2.2.8
)
