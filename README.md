# judge-k8s

A attestation validator for Kubernetes

## Development

Set up K3d cluster and start Skaffold

```
k3d registry create
k3d cluster create --registry-use k3d-registry:34751
skaffold dev
```

