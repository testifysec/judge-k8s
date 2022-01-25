# judge-k8s

A attestation validator for Kubernetes

## Development

Set up K3d cluster and start Skaffold

```
k3d registry create --port 0.0.0.0:34751 skafold-dev
k3d cluster create --registry-use skafold-dev:34751
skaffold dev
```

