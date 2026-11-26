from typing import Any, Dict, List, Tuple


class K8sHardening:
    """
    Auditor y generador de manifiestos Kubernetes fortalecidos (*PodSecurityStandards*).
    Aplica restricciones de SecurityContext (runAsNonRoot, readOnlyRootFilesystem, drop ALL capabilities).
    """

    WORKLOAD_KINDS = frozenset({
        "Pod", "Deployment", "StatefulSet", "DaemonSet",
        "ReplicaSet", "ReplicationController", "Job", "CronJob",
    })

    K8S_POD_TEMPLATE = """apiVersion: v1
kind: Pod
metadata:
  name: {name}-hardened
  labels:
    app: {name}
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: {name}
    image: {image}
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
    resources:
      limits:
        cpu: "500m"
        memory: "512Mi"
      requests:
        cpu: "100m"
        memory: "128Mi"
"""

    @staticmethod
    def generate_hardened_pod_manifest(name: str = "myapp", image: str = "myapp:1.0.0") -> str:
        """
        Genera un manifiesto YAML de Pod Kubernetes con SecurityContext fortalecido.
        """
        return K8sHardening.K8S_POD_TEMPLATE.format(name=name, image=image)

    @staticmethod
    def _extract_pod_spec(manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Extrae el PodSpec desde un Pod o workload (Deployment, StatefulSet, Job, CronJob...)."""
        if not isinstance(manifest, dict):
            return {}
        kind = manifest.get("kind")
        spec = K8sHardening._child(manifest, "spec")
        if kind == "CronJob":
            job_spec = K8sHardening._child(K8sHardening._child(spec, "jobTemplate"), "spec")
            return K8sHardening._child(K8sHardening._child(job_spec, "template"), "spec")
        if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job"}:
            return K8sHardening._child(K8sHardening._child(spec, "template"), "spec")
        return spec

    @staticmethod
    def _child(mapping: Dict[str, Any], key: str) -> Dict[str, Any]:
        """El diccionario bajo key, o {} si falta o no es un diccionario (un `spec:` vacío es None)."""
        value = mapping.get(key)
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _audit_containers(
        containers: Any,
        *,
        label: str,
        findings: List[Tuple[str, str, str]],
    ) -> None:
        if not isinstance(containers, list):
            return
        for c in containers:
            if not isinstance(c, dict):
                continue
            c_name = c.get("name", "container")
            raw_sec = c.get("securityContext")
            c_sec = raw_sec if isinstance(raw_sec, dict) else {}

            if c_sec.get("allowPrivilegeEscalation") is not False:
                findings.append((
                    f"{label}({c_name}).allowPrivilegeEscalation",
                    "ALTO",
                    "Falta 'allowPrivilegeEscalation: false'.",
                ))

            if not c_sec.get("readOnlyRootFilesystem"):
                findings.append((
                    f"{label}({c_name}).readOnlyRootFilesystem",
                    "MEDIO",
                    "Falta 'readOnlyRootFilesystem: true'.",
                ))

            caps = c_sec.get("capabilities")
            caps_dict = caps if isinstance(caps, dict) else {}
            drop = caps_dict.get("drop")
            drop_list = drop if isinstance(drop, (list, tuple)) else []
            if not any(str(cap).upper() == "ALL" for cap in drop_list):
                findings.append((
                    f"{label}({c_name}).capabilities.drop",
                    "MEDIO",
                    "Falta 'drop: [ALL]' en capacidades de Linux.",
                ))

    @staticmethod
    def audit_pod_security_context(pod_dict: Dict[str, Any]) -> List[Tuple[str, str, str]]:
        """
        Audita un diccionario de Pod o workload Kubernetes comprobando directivas de SecurityContext.
        """
        findings: List[Tuple[str, str, str]] = []
        kind_label = str((pod_dict or {}).get("kind") or "Pod") if isinstance(pod_dict, dict) else "Pod"
        spec = K8sHardening._extract_pod_spec(pod_dict)
        raw_pod_sec = spec.get("securityContext")
        pod_sec = raw_pod_sec if isinstance(raw_pod_sec, dict) else {}

        if not pod_sec.get("runAsNonRoot"):
            findings.append((
                f"{kind_label}.spec.securityContext.runAsNonRoot",
                "ALTO",
                "Falta 'runAsNonRoot: true'. El contenedor podría ejecutarse como root.",
            ))

        K8sHardening._audit_containers(spec.get("containers"), label="Container", findings=findings)
        K8sHardening._audit_containers(spec.get("initContainers"), label="InitContainer", findings=findings)

        if not findings:
            findings.append(("Kubernetes Pod", "OK", "El manifiesto cumple con los estándares restringidos de PodSecurity."))

        return findings
