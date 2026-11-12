{{- define "xmsg.fullname" -}}
{{- printf "%s-xmsg" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "xmsg.selectorLabels" -}}
app.kubernetes.io/name: xmsg
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}
{{- define "xmsg.labels" -}}
{{ include "xmsg.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
{{- end -}}
