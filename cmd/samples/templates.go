// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package samples

const (
	nativeEnvoyConfig = `admin:
access_log_path: /tmp/envoy_admin.log
address:
  socket_address:
    address: 127.0.0.1
    port_value: 9000

static_resources:
listeners:
- address:
    socket_address: { address: 0.0.0.0, port_value: 8080 }

  filter_chains:
  - filters:
    - name: envoy.filters.network.http_connection_manager
      typed_config:  
        "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
        stat_prefix: ingress_http
        route_config:
          virtual_hosts:
          - name: default
            domains: "*"
            routes:
            - match: { prefix: {{.TargetService.Prefix}} }
              route:
                cluster: {{.TargetService.Name}}
              typed_per_filter_config:
                envoy.filters.http.dynamic_forward_proxy:
                  "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.PerRouteConfig
                  host_rewrite_literal: {{.TargetService.Host}}  # rewrites :authority for Apigee product check

        http_filters:

        - name: envoy.filters.http.dynamic_forward_proxy
          typed_config:
            "@type": type.googleapis.com/envoy.config.filter.http.dynamic_forward_proxy.v2alpha.FilterConfig
            dns_cache_config:
              name: dynamic_forward_proxy_cache_config
              dns_lookup_family: V4_ONLY

        # evaluate JWT tokens, allow_missing allows API Key also
        - name: envoy.filters.http.jwt_authn
          typed_config: 
            "@type": type.googleapis.com/envoy.config.filter.http.jwt_authn.v2alpha.JwtAuthentication
            providers:
              apigee:
                issuer: https://{{.RuntimeHost}}/remote-service/token
                audiences:
                - remote-service-client
                remote_jwks:
                  http_uri:
                    uri: https://{{.RuntimeHost}}/remote-service/certs
                    cluster: apigee-auth-service
                    timeout: 5s
                  cache_duration:
                    seconds: 300
                payload_in_metadata: apigee
            rules:
            - match:
                prefix: /
              requires:
                requires_any:
                  requirements:
                  - provider_name: apigee
                  - allow_missing: {}

        # evaluate Apigee rules
        - name: envoy.filters.http.ext_authz
          typed_config:
            "@type": type.googleapis.com/envoy.config.filter.http.ext_authz.v2.ExtAuthz
            grpc_service:
              envoy_grpc:
                cluster_name: apigee-remote-service-envoy
              timeout: 1s                
            metadata_context_namespaces:
            - envoy.filters.http.jwt_authn

        # evaluate RBAC (necessary for Apigee config: reject_unauthorized == false)
        - name: envoy.filters.http.rbac
          typed_config:
            "@type": type.googleapis.com/envoy.config.filter.http.rbac.v2.RBAC
            rules:
              action: ALLOW
              policies:
                apigee-connector:
                  principals:
                  - any: true
                  permissions:
                  - header: { "name": "X-Apigee-Authorized" }

        - name: envoy.filters.http.router
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

        access_log: 

        # collect Apigee analytics
        - name: envoy.access_loggers.http_grpc
          typed_config:
            "@type": type.googleapis.com/envoy.config.accesslog.v2.HttpGrpcAccessLogConfig
            common_config:
              grpc_service:
                envoy_grpc:
                  cluster_name: apigee-remote-service-envoy
              log_name: apigee-remote-service-envoy
            additional_request_headers_to_log:
            - :authority # default target header
            # context headers
            - x-apigee-accesstoken
            - x-apigee-api
            - x-apigee-apiproducts
            - x-apigee-application
            - x-apigee-clientid
            - x-apigee-developeremail

clusters:
  
# define cluster for {{.TargetService.Host}} target
- name: {{.TargetService.Name}}
  connect_timeout: 2s
  type: LOGICAL_DNS
  dns_lookup_family: V4_ONLY
  lb_policy: ROUND_ROBIN
  load_assignment:
    cluster_name: {{.TargetService.Name}}
    endpoints:
    - lb_endpoints:
      - endpoint:
          address:
            socket_address:
              address: {{.TargetService.Host}}
              port_value: 443
  transport_socket:
    name: envoy.transport_sockets.tls
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
      sni: {{.TargetService.Host}}

# define cluster for Apigee remote service
- name: apigee-remote-service-envoy
  type: static
  http2_protocol_options: {}
  load_assignment:
    cluster_name: apigee-remote-service-envoy
    endpoints:
    - lb_endpoints:
      - endpoint:
          address:
            socket_address:
              address: 127.0.0.1
              port_value: 5000
  common_lb_config:
    healthy_panic_threshold:
      value: 50.0
  health_checks:
    - timeout: 1s
      interval: 5s
      interval_jitter: 1s
      no_traffic_interval: 5s
      unhealthy_threshold: 1
      healthy_threshold: 3
      grpc_health_check: {}
  connect_timeout: 0.25s
  {{if .TLS}}
  # for custom SSL connection to remote-service
  transport_socket: 
    name: envoy.transport_sockets.tls
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
      common_tls_context:
        tls_certificates: 
        - certificate_chain: {{.TLS.Crt}}
          private_key: {{.TLS.Key}}
  {{end}}

# define cluster for Apigee JWKS certs
- name: apigee-auth-service
  connect_timeout: 2s
  type: LOGICAL_DNS
  dns_lookup_family: V4_ONLY
  lb_policy: ROUND_ROBIN
  load_assignment:
    cluster_name: apigee-auth-service
    endpoints:
    - lb_endpoints:
      - endpoint:
          address:
            socket_address:
              address: {{.RuntimeHost}}
              port_value: 443
  transport_socket:
    name: envoy.transport_sockets.tls
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
      sni: {{.RuntimeHost}}
`

	adapterConfig = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: apigee-remote-service-envoy
  namespace: {{.Namespace}}
  annotations:
    sidecar.istio.io/rewriteAppHTTPProbers: "true"
    prometheus.io/path: /metrics
    prometheus.io/port: "5001"
    prometheus.io/scheme: https
    prometheus.io/scrape: "true"
    prometheus.io/type: prometheusspec
spec:
  replicas: 1
  selector:
    matchLabels:
      app: apigee-remote-service-envoy
  template:
    metadata:
      labels:
        app: apigee-remote-service-envoy
        version: v1
    spec:
      securityContext:  
        runAsUser: 999
        runAsGroup: 999
        runAsNonRoot: true
      containers:
      - name: apigee-remote-service-envoy
        image: "google/apigee-envoy-adapter:v1.0.0"
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 5000
        livenessProbe:
          httpGet:
            path: /healthz
            port: 5001
          failureThreshold: 1
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /healthz
            port: 5001
          failureThreshold: 30
          periodSeconds: 10
        args:
          - --log-level=debug
          - --config=/config/config.yaml
        resources:
          limits:
            cpu: 100m
            memory: 100Mi
          requests:
            cpu: 10m
            memory: 100Mi
        volumeMounts:
        - mountPath: /config
          name: apigee-remote-service-envoy
          readOnly: true
        - mountPath: /opt/apigee/tls
          name: tls-volume
          readOnly: true
        - mountPath: /policy-secret
          name: policy-secret
          readOnly: true
      volumes:
      - name: apigee-remote-service-envoy
        configMap:
          name: apigee-remote-service-envoy
      - name: tls-volume
        secret:
          defaultMode: 420
          secretName: apigee-udca-{{.EncodedName}}-tls
      - name: policy-secret
        secret:
          defaultMode: 420
          secretName: {{.Org}}-{{.Env}}-policy-secret
---
apiVersion: v1
kind: Service
metadata:
  name: apigee-remote-service-envoy
  namespace: {{.Namespace}}
  labels:
    app: apigee-remote-service-envoy
spec:
  ports:
  - port: 5000
    name: grpc
  selector:
    app: apigee-remote-service-envoy
`

	envoyFilterSidecar = `# Installs an Istio EnvoyFilter in the default namespace.
# It applies to all services in the namespace. If you wish, you
# may tailor by specifying "workloadSelector" for specific targets.
# Uses "apigee-remote-service-envoy.apigee:5000" as target.

# This is known to work through Istio 1.6.
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: apigee-remote-{{.TargetService.Name}}
  namespace: default
spec:
  workloadSelector:
    labels:
      managed-by: apigee
  configPatches:

  - applyTo: HTTP_FILTER
    match:
      context: SIDECAR_INBOUND
      listener:
        filterChain:
          filter:
            name: envoy.http_connection_manager
            subFilter:
              name: envoy.router
    
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.ext_authz
        config:
          grpc_service:
            google_grpc:
              target_uri: apigee-remote-service-envoy.apigee:5000
              stat_prefix: apigee-remote-service
            timeout: 1s
          metadata_context_namespaces:
            - envoy.filters.http.jwt_authn

  - applyTo: HTTP_FILTER
    match:
      context: SIDECAR_INBOUND
      listener:
        filterChain:
          filter:
            name: envoy.http_connection_manager
            subFilter:
              name: envoy.ext_authz
    
    patch:
      operation: INSERT_AFTER
      value:
        name: envoy.filters.http.rbac
        config:
          rules:
            action: ALLOW
            policies:
              apigee-connector:
                principals:
                - any: true
                permissions:
                - header: { "name": "X-Apigee-Authorized" }

  - applyTo: NETWORK_FILTER
    match:
      context: SIDECAR_INBOUND
      listener:
        filterChain:
          filter:
            name: "envoy.http_connection_manager"
    patch:
      operation: MERGE
      value:
        typed_config:
          "@type": "type.googleapis.com/envoy.config.filter.network.http_connection_manager.v2.HttpConnectionManager"
          access_log:
          - name: envoy.http_grpc_access_log
            config:
              common_config:
                log_name: apigee-remote-service
                grpc_service:
                  google_grpc:
                    target_uri: apigee-remote-service-envoy.apigee:5000
                    stat_prefix: apigee-remote-service
              additional_request_headers_to_log:
              - :authority # default target header
              # context headers
              - x-apigee-accesstoken
              - x-apigee-api
              - x-apigee-apiproducts
              - x-apigee-application
              - x-apigee-clientid
              - x-apigee-developeremail
`

	requestAuthentication = `apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: apigee
  namespace: default
spec:
  selector:
    matchLabels:
      managed-by: apigee
  jwtRules:
  - issuer: https://{{.RuntimeHost}}/remote-service/token
    jwksUri: https://{{.RuntimeHost}}/remote-service/certs
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: apigee
  namespace: default
spec:
  selector:
  matchLabels:
    managed-by: apigee
  rules:
  - from:
    - source:
        requestPrincipals: ["*"]
`

	httpbinConfig = `# An httpbin target example Deployment and Service.
apiVersion: v1
kind: Service
metadata:
  name: httpbin
  namespace: default
  labels:
    app: httpbin
spec:
  ports:
  - name: http
    port: 80
    targetPort: 80
  selector:
    app: httpbin
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: httpbin
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: httpbin
      version: v1
  template:
    metadata:
      labels:
        app: httpbin
        version: v1
        managed-by: apigee
    spec:
      containers:
      - image: docker.io/kennethreitz/httpbin
        imagePullPolicy: IfNotPresent
        name: httpbin
        ports:
        - containerPort: 80
`
)
