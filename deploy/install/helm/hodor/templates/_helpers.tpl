{{/* The name every resource of the release starts with. */}}
{{- define "hodor.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 52 | trimSuffix "-" -}}
{{- else if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 52 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 52 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* The labels that select the pods of this release, whatever their part. */}}
{{- define "hodor.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* The labels every resource carries. */}}
{{- define "hodor.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "hodor.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* The image, with the version of the chart when no tag is given. */}}
{{- define "hodor.image" -}}
{{- $repository := required "image.repository is required: where the Hodor image is, such as registry.example.com/hodor" .Values.image.repository -}}
{{- printf "%s:%s" $repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}

{{/* The name of the Secret that holds the passwords and keys. */}}
{{- define "hodor.secretName" -}}
{{- required "secret.name is required: the Secret that holds the database addresses and the secret keys" .Values.secret.name -}}
{{- end -}}

{{/* The address people use, checked. */}}
{{- define "hodor.publicUrl" -}}
{{- $url := required "publicUrl is required: the address people use, such as https://login.example.com" .Values.publicUrl -}}
{{- if not (regexMatch "^https?://[^/]+$" $url) -}}
{{- fail (printf "publicUrl must be http or https, a name and no path, such as https://login.example.com; it is %q" $url) -}}
{{- end -}}
{{- $url -}}
{{- end -}}

{{/* The name of the service account the servers and workers run as. */}}
{{- define "hodor.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- .Values.serviceAccount.name | default (include "hodor.fullname" .) -}}
{{- else -}}
{{- required "serviceAccount.name is required when serviceAccount.create is false" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* What no Hodor pod may do: run as root, gain privileges, or use a system call outside the default set. */}}
{{- define "hodor.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/* What no Hodor container may do: write to its own files, or hold any capability. */}}
{{- define "hodor.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
{{- end -}}

{{/* One environment variable read from the Secret. Takes a list: the context, the variable, the key. */}}
{{- define "hodor.secretEnvironment" -}}
{{- $root := index . 0 -}}
- name: {{ index . 1 }}
  valueFrom:
    secretKeyRef:
      name: {{ include "hodor.secretName" $root }}
      key: {{ index . 2 }}
{{- end -}}

{{/* The environment variables the server and the worker share. */}}
{{- define "hodor.sharedEnvironment" -}}
- name: HODOR_OPS_ADDR
  value: "0.0.0.0:9090"
- name: HODOR_LOG_FORMAT
  value: {{ .Values.log.format | quote }}
- name: HODOR_LOG_FILTER
  value: {{ .Values.log.filter | quote }}
{{- with .Values.telemetry.metricsEndpoint }}
- name: HODOR_OTLP_METRICS_ENDPOINT
  value: {{ . | quote }}
{{- end }}
{{- with .Values.telemetry.tracesEndpoint }}
- name: HODOR_OTLP_TRACES_ENDPOINT
  value: {{ . | quote }}
{{- end }}
{{- end -}}

{{/* The three health checks, on the operations port. Starting may take a minute; after that, a pod that
     stops answering is restarted, and one whose database is unreachable stops receiving requests. */}}
{{- define "hodor.probes" -}}
startupProbe:
  httpGet:
    path: /startupz
    port: operations
  periodSeconds: 2
  failureThreshold: 30
readinessProbe:
  httpGet:
    path: /readyz
    port: operations
  periodSeconds: 5
  failureThreshold: 2
livenessProbe:
  httpGet:
    path: /livez
    port: operations
  periodSeconds: 10
  failureThreshold: 3
{{- end -}}

{{/* Pods of one part spread across zones and nodes, when the cluster has more than one. Takes a list:
     the context, the part. */}}
{{- define "hodor.spread" -}}
{{- $root := index . 0 -}}
topologySpreadConstraints:
  {{- range $key := list "topology.kubernetes.io/zone" "kubernetes.io/hostname" }}
  - maxSkew: 1
    topologyKey: {{ $key }}
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        {{- include "hodor.selectorLabels" $root | nindent 8 }}
        app.kubernetes.io/component: {{ index $ 1 }}
  {{- end }}
{{- end -}}

{{/* The environment of the key providers, the same for the servers and the workers: the worker makes the
     signing keys the servers sign with (docs/operations/keys-in-openbao.md). */}}
{{- define "hodor.keyProviderEnvironment" -}}
{{- $provider := .Values.keyProvider -}}
{{- $openbao := $provider.openbao -}}
{{- if not (has $provider.signingKeys (list "local" "openbao")) -}}
{{- fail (printf "keyProvider.signingKeys is local or openbao; it is %q" $provider.signingKeys) -}}
{{- end -}}
{{- if and (eq $provider.signingKeys "openbao") (not $openbao.enabled) -}}
{{- fail "keyProvider.signingKeys is openbao: keyProvider.openbao.enabled must be true" -}}
{{- end -}}
- name: HODOR_KEY_PROVIDER
  value: {{ $provider.signingKeys | quote }}
{{- if $openbao.enabled }}
{{- if not $openbao.address }}
{{- fail "keyProvider.openbao.address is required when keyProvider.openbao.enabled is true, such as https://openbao.openbao.svc:8200" }}
{{- end }}
{{- if not (has $openbao.authMethod (list "kubernetes" "approle")) }}
{{- fail (printf "keyProvider.openbao.authMethod is kubernetes or approle; it is %q" $openbao.authMethod) }}
{{- end }}
- name: HODOR_OPENBAO_ADDRESS
  value: {{ $openbao.address | quote }}
- name: HODOR_OPENBAO_TRANSIT_MOUNT
  value: {{ $openbao.transitMount | quote }}
- name: HODOR_OPENBAO_AUTH_METHOD
  value: {{ $openbao.authMethod | quote }}
{{- with $openbao.authMount }}
- name: HODOR_OPENBAO_AUTH_MOUNT
  value: {{ . | quote }}
{{- end }}
- name: HODOR_OPENBAO_TIMEOUT_MS
  value: {{ $openbao.timeoutMs | quote }}
{{- if eq $openbao.authMethod "kubernetes" }}
- name: HODOR_OPENBAO_KUBERNETES_ROLE
  value: {{ $openbao.kubernetesRole | quote }}
- name: HODOR_OPENBAO_KUBERNETES_TOKEN_FILE
  value: /var/run/secrets/openbao/token
{{- else }}
{{ include "hodor.secretEnvironment" (list . "HODOR_OPENBAO_APPROLE_ROLE_ID" .Values.secret.keys.openbaoRoleId) }}
{{ include "hodor.secretEnvironment" (list . "HODOR_OPENBAO_APPROLE_SECRET_ID" .Values.secret.keys.openbaoSecretId) }}
{{- end }}
{{- if $openbao.certificateAuthority.configMap }}
- name: HODOR_OPENBAO_CA_FILE
  value: {{ printf "/etc/hodor/openbao/%s" $openbao.certificateAuthority.key | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{/* Where the key providers' files are mounted in the container: the token of the service account that
     OpenBao checks, and the authority of OpenBao's certificate. */}}
{{- define "hodor.keyProviderVolumeMounts" -}}
{{- $openbao := .Values.keyProvider.openbao -}}
{{- if $openbao.enabled }}
{{- if eq $openbao.authMethod "kubernetes" }}
- name: openbao-token
  mountPath: /var/run/secrets/openbao
  readOnly: true
{{- end }}
{{- if $openbao.certificateAuthority.configMap }}
- name: openbao-authority
  mountPath: /etc/hodor/openbao
  readOnly: true
{{- end }}
{{- end }}
{{- end -}}

{{/* The volumes behind those mounts. The token is the service account's, for OpenBao's audience alone,
     replaced by the kubelet before it expires; the pods mount no other token. */}}
{{- define "hodor.keyProviderVolumes" -}}
{{- $openbao := .Values.keyProvider.openbao -}}
{{- if $openbao.enabled }}
{{- if eq $openbao.authMethod "kubernetes" }}
- name: openbao-token
  projected:
    sources:
      - serviceAccountToken:
          audience: {{ $openbao.tokenAudience | quote }}
          expirationSeconds: 3600
          path: token
{{- end }}
{{- if $openbao.certificateAuthority.configMap }}
- name: openbao-authority
  configMap:
    name: {{ $openbao.certificateAuthority.configMap | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{/* The authorities of outboundAuthorities, for the servers and the workers: the variable that points
     the TLS library at the file in place of the image's authorities, where the file is mounted, and the
     ConfigMap it is read from. Each renders nothing when no ConfigMap is named. */}}
{{- define "hodor.authoritiesEnvironment" -}}
{{- with .Values.outboundAuthorities.configMap }}
- name: SSL_CERT_FILE
  value: {{ printf "/etc/hodor/authorities/%s" $.Values.outboundAuthorities.key | quote }}
{{- end }}
{{- end -}}

{{- define "hodor.authoritiesVolumeMounts" -}}
{{- with .Values.outboundAuthorities.configMap }}
- name: outbound-authorities
  mountPath: /etc/hodor/authorities
  readOnly: true
{{- end }}
{{- end -}}

{{- define "hodor.authoritiesVolumes" -}}
{{- with .Values.outboundAuthorities.configMap }}
- name: outbound-authorities
  configMap:
    name: {{ . | quote }}
    items:
      - key: {{ $.Values.outboundAuthorities.key }}
        path: {{ $.Values.outboundAuthorities.key }}
{{- end }}
{{- end -}}

{{/* The name of the service account hodor-ext-authz runs as, which gives it its mesh identity. */}}
{{- define "hodor.extAuthzServiceAccountName" -}}
{{- if .Values.extAuthz.serviceAccount.create -}}
{{- .Values.extAuthz.serviceAccount.name | default (printf "%s-ext-authz" (include "hodor.fullname" .)) -}}
{{- else -}}
{{- required "extAuthz.serviceAccount.name is required when extAuthz.serviceAccount.create is false" .Values.extAuthz.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* The configuration file of hodor-ext-authz, written from extAuthz as docs/operations/hodor-ext-authz.md
     describes it. */}}
{{- define "hodor.extAuthzConfig" -}}
{{- $tenant := required "extAuthz.tenant is required when extAuthz.enabled is true: the tenant's slug" .Values.extAuthz.tenant -}}
{{- $url := .Values.extAuthz.hodorUrl | default (printf "http://%s.%s.svc.cluster.local:%v" (include "hodor.fullname" .) .Release.Namespace .Values.service.port) -}}
{{- $issuer := .Values.extAuthz.issuer | default (printf "%s/t/%s" (include "hodor.publicUrl" .) $tenant) -}}
{{- $hodor := dict "url" $url "tenant" $tenant "issuer" $issuer "timeout_milliseconds" (int .Values.extAuthz.timeoutMilliseconds) -}}
{{- $config := dict "hodor" $hodor -}}
{{- with .Values.extAuthz.token }}
{{- $_ := set $config "token" . -}}
{{- end }}
{{- $applications := list -}}
{{- range $index, $application := .Values.extAuthz.applications }}
{{- $routes := list -}}
{{- range $application.routes }}
{{- $routes = append $routes (dict "methods" .methods "path" .path "resource_type" .resourceType "action" .action) -}}
{{- end }}
{{- $applications = append $applications (dict "destination" (required (printf "extAuthz.applications[%d].destination is required" $index) $application.destination) "client_id" (required (printf "extAuthz.applications[%d].clientId is required" $index) $application.clientId) "routes" $routes) -}}
{{- end }}
{{- $_ := set $config "applications" $applications -}}
{{- $config | toPrettyJson -}}
{{- end -}}

{{/* Whether the release holds Hodor itself: always, unless it holds cert-manager's issuer alone. Renders
     "true" or nothing. */}}
{{- define "hodor.installsHodor" -}}
{{- if not (and .Values.certManagerIssuer.enabled .Values.certManagerIssuer.only) -}}
true
{{- end -}}
{{- end -}}

{{/* The name of the service account hodor-cert-manager-issuer runs as, which its ClusterRole is bound to. */}}
{{- define "hodor.certManagerIssuerServiceAccountName" -}}
{{- if .Values.certManagerIssuer.serviceAccount.create -}}
{{- .Values.certManagerIssuer.serviceAccount.name | default (printf "%s-cert-manager-issuer" (include "hodor.fullname" .)) -}}
{{- else -}}
{{- required "certManagerIssuer.serviceAccount.name is required when certManagerIssuer.serviceAccount.create is false" .Values.certManagerIssuer.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* The configuration file of hodor-cert-manager-issuer, written from certManagerIssuer as
     docs/operations/hodor-cert-manager-issuer.md describes it. */}}
{{- define "hodor.certManagerIssuerConfig" -}}
{{- $values := .Values.certManagerIssuer -}}
{{- $tenant := required "certManagerIssuer.tenant is required when certManagerIssuer.enabled is true: the tenant's slug" $values.tenant -}}
{{- $clientId := required "certManagerIssuer.clientId is required when certManagerIssuer.enabled is true: the client of the issuer's service account in Hodor" $values.clientId -}}
{{- $url := "" -}}
{{- if $values.only -}}
{{- $url = required "certManagerIssuer.hodorUrl is required with certManagerIssuer.only: where the issuer reaches Hodor, such as https://login.example.com" $values.hodorUrl -}}
{{- else -}}
{{- $url = $values.hodorUrl | default (printf "http://%s.%s.svc.cluster.local:%v" (include "hodor.fullname" .) .Release.Namespace .Values.service.port) -}}
{{- end -}}
{{- $issuer := $values.issuer -}}
{{- if not $issuer -}}
{{- if $values.only -}}
{{- $issuer = printf "%s/t/%s" (trimSuffix "/" $url) $tenant -}}
{{- else -}}
{{- $issuer = printf "%s/t/%s" (include "hodor.publicUrl" .) $tenant -}}
{{- end -}}
{{- end -}}
{{- $method := $values.authentication.method -}}
{{- $authentication := dict "method" $method -}}
{{- if eq $method "private_key_jwt" -}}
{{- $_ := required "certManagerIssuer.authentication.privateKeyJwt.secretName is required with private_key_jwt: the Secret that holds the client's key" $values.authentication.privateKeyJwt.secretName -}}
{{- $_ := set $authentication "key_file" "/etc/hodor-cert-manager-issuer/key/key.pem" -}}
{{- with $values.authentication.privateKeyJwt.keyId }}
{{- $_ := set $authentication "key_id" . -}}
{{- end }}
{{- else if ne $method "forwarded" -}}
{{- fail (printf "certManagerIssuer.authentication.method is forwarded or private_key_jwt; it is %q" $method) -}}
{{- end -}}
{{- $hodor := dict "url" $url "tenant" $tenant "issuer" $issuer "timeout_milliseconds" (int $values.timeoutMilliseconds) -}}
{{- $config := dict "hodor" $hodor "client" (dict "client_id" $clientId "authentication" $authentication) -}}
{{- $config | toPrettyJson -}}
{{- end -}}


{{/* The service mesh of mesh.provider, checked: istio, linkerd, or empty for none. */}}
{{- define "hodor.meshProvider" -}}
{{- $provider := .Values.mesh.provider | default "" -}}
{{- if not (has $provider (list "" "istio" "linkerd")) -}}
{{- fail (printf "mesh.provider must be istio, linkerd or empty; it is %q" $provider) -}}
{{- end -}}
{{- $provider -}}
{{- end -}}

{{/* The labels that put a pod in the mesh, or keep it out. Takes a list: the context, and whether the pod
     joins the mesh. */}}
{{- define "hodor.meshLabels" -}}
{{- $root := index . 0 -}}
{{- if eq (include "hodor.meshProvider" $root) "istio" -}}
sidecar.istio.io/inject: {{ ternary "true" "false" (index . 1) | quote }}
{{- end -}}
{{- end -}}

{{/* The annotations of a pod in the mesh, as YAML. The operations port, where the health checks are, stays
     out of the proxy, so that the kubelet reaches it directly. Takes a list: the context, and whether the pod
     joins the mesh. */}}
{{- define "hodor.meshAnnotations" -}}
{{- $root := index . 0 -}}
{{- $joins := index . 1 -}}
{{- $provider := include "hodor.meshProvider" $root -}}
{{- $skipped := join "," $root.Values.mesh.skipOutboundPorts -}}
{{- if and (eq $provider "istio") $joins }}
traffic.sidecar.istio.io/excludeInboundPorts: "9090"
proxy.istio.io/config: '{"holdApplicationUntilProxyStarts": true}'
{{- with $skipped }}
traffic.sidecar.istio.io/excludeOutboundPorts: {{ . | quote }}
{{- end }}
{{- else if eq $provider "linkerd" }}
linkerd.io/inject: {{ ternary "enabled" "disabled" $joins }}
{{- if $joins }}
config.linkerd.io/skip-inbound-ports: "9090"
{{- with $skipped }}
config.linkerd.io/skip-outbound-ports: {{ . | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- end -}}

{{/* The annotations of a pod: the mesh's, then the ones given, which win. Takes a list: the context, whether
     the pod joins the mesh, and the annotations given. */}}
{{- define "hodor.podAnnotations" -}}
{{- $mesh := include "hodor.meshAnnotations" (list (index . 0) (index . 1)) | fromYaml | default dict -}}
{{- $all := merge (dict) ((index . 2) | default dict) $mesh -}}
{{- with $all }}
annotations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/* HODOR_TRUSTED_PROXIES: trustedProxies, and the proxy beside Hodor in a mesh. Istio's sidecar connects
     from 127.0.0.6, or ::6; Linkerd's from the pod's own addresses, in POD_ADDRESSES. */}}
{{- define "hodor.trustedProxies" -}}
{{- $ranges := .Values.trustedProxies | default list -}}
{{- $provider := include "hodor.meshProvider" . -}}
{{- if eq $provider "istio" -}}
{{- $ranges = concat $ranges (list "127.0.0.6" "::6") -}}
{{- else if eq $provider "linkerd" -}}
{{- $ranges = concat $ranges (list "$(POD_ADDRESSES)") -}}
{{- end -}}
{{- join "," $ranges -}}
{{- end -}}

{{/* HODOR_CLIENT_IDENTITY_HEADER: clientIdentityHeader, or the header of the mesh. */}}
{{- define "hodor.clientIdentityHeader" -}}
{{- $provider := include "hodor.meshProvider" . -}}
{{- $mesh := get (dict "istio" "x-forwarded-client-cert" "linkerd" "l5d-client-id") $provider -}}
{{- .Values.clientIdentityHeader | default $mesh -}}
{{- end -}}

{{/* HODOR_FORWARDED_HEADER: forwardedHeader, unless Hodor is in a mesh and no gateway is named. The proxy
     beside Hodor passes X-Forwarded-For as any caller wrote it, so then none is read. */}}
{{- define "hodor.forwardedHeader" -}}
{{- if and (include "hodor.meshProvider" .) (not .Values.gatewayIdentities) -}}
none
{{- else -}}
{{- .Values.forwardedHeader -}}
{{- end -}}
{{- end -}}

{{/* The gateways of gatewayIdentities, refused when the server could never recognize them. */}}
{{- define "hodor.gatewayIdentities" -}}
{{- with .Values.gatewayIdentities -}}
{{- if not (include "hodor.trustedProxies" $) -}}
{{- fail "gatewayIdentities needs trustedProxies or mesh.provider: the proxy that forwards the gateway's identity" -}}
{{- end -}}
{{- if not (include "hodor.clientIdentityHeader" $) -}}
{{- fail "gatewayIdentities needs clientIdentityHeader or mesh.provider: the header the gateway's identity arrives in" -}}
{{- end -}}
{{- if eq (include "hodor.forwardedHeader" $) "none" -}}
{{- fail "gatewayIdentities needs a forwardedHeader other than none: the header the gateways' forwarded address is read from" -}}
{{- end -}}
{{- join "," . -}}
{{- end -}}
{{- end -}}

{{/* The namespace of the mesh's control plane, or nothing outside a mesh. */}}
{{- define "hodor.meshControlPlane" -}}
{{- $provider := include "hodor.meshProvider" . -}}
{{- if $provider -}}
{{- .Values.mesh.controlPlaneNamespace | default (get (dict "istio" "istio-system" "linkerd" "linkerd") $provider) -}}
{{- end -}}
{{- end -}}
