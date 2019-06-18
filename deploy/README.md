# Deploy manifests for Kubernetes

The manfiests in this directory can be used to install the operator on a Kubernetes cluster. They are
primarily intended for developers, are not guaranteed to be stable, and may be changed or broken at
any time without notice.

## Using these manifests

1. First install the operator's CRD:

	kubectl apply -f crds/operator-crd.yaml

1. The operator manifests are found in this directory.

	kubectl apply -f .

1. Install the configuration CRD.

	kubectl apply -f crds/default.yaml
