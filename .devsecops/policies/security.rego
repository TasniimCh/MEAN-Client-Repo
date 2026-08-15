package main

deny contains {
    "policy_id": "K8S-001",
    "severity": "high",
    "message": "Container must run as non-root",
} if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot
}