[![<CirclCI>](https://circleci.com/gh/theganyo/apigee-remote-service-cli.svg?style=svg)](https://circleci.com/gh/theganyo/apigee-remote-service-cli)
[![Go Report Card](https://goreportcard.com/badge/github.com/theganyo/apigee-remote-service-cli)](https://goreportcard.com/report/github.com/theganyo/apigee-remote-service-cli)
[![codecov.io](https://codecov.io/github/theganyo/apigee-remote-service-cli/coverage.svg?branch=master)](https://codecov.io/github/theganyo/apigee-remote-service-cli?branch=master)

# Apigee Remote Service CLI

Apigee's CLI for remote gateway service. This includes the "remote-service"
proxy istalled into Apigee Runtime.

# Usage

## Prerequisite: Apigee

You must have an [Apigee](https://cloud.google.com/apigee/) account. 
[Try it free](https://login.apigee.com/sign__up) if you don't!

## Download a release

Releases can be found [here](../../releases).

Download the appropriate release package for your operating system and 
extract it. You'll see a top-level list similar to:

    LICENSE
    README.md
    apigee-remote-service-cli

`apigee-remote-service-cli` (or apigee-remote-service-cli.exe on Windows) 
is the Command Line Interface (CLI) for this project. Add it to your PATH
for quick access (or remember to specify the path for the commands below).

## Provision Apigee

The first thing you'll need to do is provision your Apigee environment to 
work with the apigee-remote-service. The `provision` command will install 
a proxy into Apigee if necessary, set up a certificate on Apigee, and
generate some credentials the remote service will use to securely connect 
back to Apigee.

_Tip_ 
You can automatically format the emitted config as a Kubernetes ConfigMap
intead of raw YAML by using the --namespace option.

_Upgrading_  
By default, running `provision` will not attempt to install a new proxy 
into your environment if one already exists. If you are upgrading from a 
prior release, add the `--forceProxyInstall` option to the commands below
to ensure that the latest proxy is installed into your environment.

### Apigee Hybrid

Apigee Hybrid 

You must be authenticated with gcloud for your hybrid project and get a
valid token:

    TOKEN=$(gcloud auth print-access-token);echo $TOKEN

Run provision to get your configuration and store it in a file:

    apigee-remote-service-cli provision --organization $ORG --environment $ENV \
        --developer-email $EMAIL --runtime $RUNTIME --namespace apigee --token $TOKEN > config.yaml

Notes:
- A `developer-email` is required for provisioning to create an `apigee-remote` Developer in Apigee. It can be whatever you want.
- The `runtime` parameter should start with `https://` and be one of the `hostAliases` in your `virtualhosts`.

Install a certificate in your Kuberentes environment:

    apigee-remote-service-cli token create-secret --config config.yaml --truncate 1 \
        --namespace apigee > secret.yaml
    kubenetes apply -f secret.yaml

Verify your proxy and certificate. The following should return valid JSON:

    curl --http1.1 -i $RUNTIME/remote-service/certs

### Apigee SaaS

    apigee-remote-service-cli provision --legacy --username $USER --password $PASSWORD \
        --organization $ORG --environment $ENV > config.yaml

_Tip_ 
The CLI will automatically pick up a username and password from a 
[.netrc](https://ec.haxx.se/usingcurl-netrc.html) file in your home 
directory if you have an entry for `api.enterprise.apigee.com`.

### Apigee OPDK

If you are running Apigee Private Cloud (OPDK), you'll need to specify 
your private server's `--management` and `--runtime` options in the 
command. The URIs must be reachable from your Istio mesh.  

    apigee-remote-service-cli provision --opdk --user $USER --password $PASSWORD \
        --organization $ORG --environment $ENV > config.yaml


Notes:
- The `runtime` parameter should be the virtual host base URL to reach your runtime.

_Tip_  
The CLI will automatically pick up a username and password from a 
[.netrc](https://ec.haxx.se/usingcurl-netrc.html) file in your home 
directory if you have an entry for your management host machine.

## Using Apigee Remote Service 

Now check out [apigee-remote-proxy-envoy](../../../apigee-remote-service-envoy) 
to put Apigee Remote Service to use with Envoy as an API proxy.

Also, check out the additional capabilities of the CLI including
binding Apigee products to target APIs and manipulating JWT tokens.

        $ apigee-remote-service-cli -h
        This command lets you interact with Apigee Remote Service

        Usage:
        apigee-remote-service-cli [command]

        Available Commands:
        bindings    Manage Apigee Product to Remote Service bindings
        help        Help about any command
        provision   Provision your Apigee environment for remote services
        token       JWT Token Utilities
        version     Prints build version - specify org and env to include proxy version

        Flags:
        -h, --help   help for apigee-remote-service-cli

        Use "apigee-remote-service-cli [command] --help" for more information about a command.
