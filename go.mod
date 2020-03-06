module github.com/apigee/apigee-proxy-cli

go 1.13

replace github.com/apigee/apigee-proxy-go => github.com/theganyo/apigee-proxy-go v0.0.0-20200305215602-1fb70f674ee6

replace github.com/apigee/apigee-proxy-cli => ./

require (
	github.com/apigee/apigee-proxy-go v0.0.0-00010101000000-000000000000
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d
	github.com/google/go-querystring v1.0.0
	github.com/lestrrat/go-jwx v0.0.0-20180221005942-b7d4802280ae
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v0.0.6
	go.uber.org/multierr v1.4.0
	gopkg.in/yaml.v2 v2.2.8
)
