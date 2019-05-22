# Operator
<img src="http://docs.projectcalico.org/images/felix.png" width="100" height="100">

This repository contains a Kubernetes operator which manages the lifecycle of a Calico installation.

Calico is a Tigera open source project, and is primarily maintained by the Tigera team. However any members of the community – individuals or organizations – are welcome to get involved and contribute to the project.

## Get Started Using Calico

For users who want to learn more about the project or get started with Calico, see the documentation on [docs.projectcalico.org](https://docs.projectcalico.org).

## Get Started Developing Calico

### Testing locally

You can create a local docker-in-docker cluster with the Makefile:

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
