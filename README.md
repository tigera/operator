# Tigera operator
<img src="http://docs.projectcalico.org/images/felix.png" width="100" height="100">

This repository contains a Kubernetes operator which manages the lifecycle of a Calico installation. It can also install [Tigera Secure Enterprise Edition](https://www.tigera.io/tigera-secure-ee/).

Calico is a Tigera open source project, and is primarily maintained by the Tigera team. However any members of the community – individuals or organizations – are welcome to get involved and contribute to the project.

### Project status

The Tigera operator is currently in tech-preview state and is not intended for production use.

### Installing the Tigera operator

For installation instructions using OpenShift v4, follow the instructions in [docs/openshift.md](docs/openshift.md).

### Testing locally

If you're doing local development, you can create a local docker-in-docker cluster with the Makefile:

	make cluster-create

Set your shell to use the local cluster:

	export KUBECONFIG="$(./k3d get-kubeconfig --name='operator-test-cluster')"

Apply the necessary CRDs (if it fails, run this command twice):

	kubectl apply -f deploy/crds
	kubectl apply -f deploy/crds/calico/

Then, build the local code:

	make build

And then, run it against your local cluster:

	WATCH_NAMESPACE="" ./build/_output/bin/operator-amd64

Finally, tear down the cluster:

	make cluster-destroy
