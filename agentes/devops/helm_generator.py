import os


class HelmGenerator:
    """
    Generador automatizado de plantillas Helm Chart para Kubernetes.
    Crea Chart.yaml, values.yaml y templates/deployment.yaml fortalecidos.
    """

    CHART_YAML = """apiVersion: v2
name: {name}
description: Helm Chart fortalecido producido por el Agente DevOps
type: application
version: 0.1.0
appVersion: "1.0.0"
"""

    VALUES_YAML = """replicaCount: 2

image:
  repository: {image_repo}
  pullPolicy: IfNotPresent
  tag: "1.0.0"

service:
  type: ClusterIP
  port: {port}

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi

securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
"""

    DEPLOYMENT_YAML = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-{{ .Chart.Name }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      app: {{ .Chart.Name }}
  template:
    metadata:
      labels:
        app: {{ .Chart.Name }}
    spec:
      securityContext:
        runAsNonRoot: {{ .Values.securityContext.runAsNonRoot }}
        runAsUser: {{ .Values.securityContext.runAsUser }}
      containers:
        - name: {{ .Chart.Name }}
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          securityContext:
            readOnlyRootFilesystem: {{ .Values.securityContext.readOnlyRootFilesystem }}
            allowPrivilegeEscalation: {{ .Values.securityContext.allowPrivilegeEscalation }}
            capabilities:
              {{- toYaml .Values.securityContext.capabilities | nindent 14 }}
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
"""

    @staticmethod
    def generate_helm_chart(
        output_dir: str,
        chart_name: str = "my-service",
        image_repo: str = "myorg/myservice",
        port: int = 80,
    ) -> str:
        """
        Crea la estructura completa de un Helm Chart en la carpeta indicada.
        """
        # Descomponer referencias repositorio:etiqueta manejando también registros privados con puerto explícito.
        repo, tag = image_repo, "1.0.0"
        if ":" in image_repo and "/" in image_repo.split(":")[0]:
            repo, tag = image_repo.rsplit(":", 1)
        elif image_repo.count(":") == 1 and not image_repo.startswith("http"):
            # Cuando no hay puerto de registro en el prefijo, un único ':' separa
            # directamente la referencia usuario/imagen de su etiqueta de versión.
            repo, tag = image_repo.rsplit(":", 1)

        os.makedirs(output_dir, exist_ok=True)
        templates_dir = os.path.join(output_dir, "templates")
        os.makedirs(templates_dir, exist_ok=True)

        values = HelmGenerator.VALUES_YAML.format(image_repo=repo, port=port)
        values = values.replace('tag: "1.0.0"', f'tag: "{tag}"')

        with open(os.path.join(output_dir, "Chart.yaml"), "w", encoding="utf-8") as f:
            f.write(HelmGenerator.CHART_YAML.format(name=chart_name))

        with open(os.path.join(output_dir, "values.yaml"), "w", encoding="utf-8") as f:
            f.write(values)

        with open(os.path.join(templates_dir, "deployment.yaml"), "w", encoding="utf-8") as f:
            f.write(HelmGenerator.DEPLOYMENT_YAML)

        return output_dir
