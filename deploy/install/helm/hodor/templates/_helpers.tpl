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
