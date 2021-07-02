module github.com/apigee/apigee-remote-service-cli/v2

go 1.16

// replace github.com/apigee/apigee-remote-service-golib/v2 => ../apigee-remote-service-golib

// replace github.com/apigee/apigee-remote-service-envoy/v2 => ../apigee-remote-service-envoy

// Cobra/Viper pulls in github.com/hashicorp/hcl which has a MPL license.
// We don't need or use this library, so replace it with a local shim.
replace github.com/hashicorp/hcl => ./hcl_shim

require (
	github.com/apigee/apigee-remote-service-envoy/v2 v2.0.2-0.20210602213744-0e7cae50b687
	github.com/apigee/apigee-remote-service-golib/v2 v2.0.2-0.20210602162200-17af2b43f25c
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d
	github.com/lestrrat-go/jwx v1.2.0
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.2.0
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)
