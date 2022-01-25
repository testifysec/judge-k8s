dev:
	@k3d registry create --port 0.0.0.0:34751 skafold-dev || true
	@k3d cluster create --registry-use skafold-dev:34751 || true
	@skaffold dev