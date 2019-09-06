# Tigera Operator

[![Build Status](https://semaphoreci.com/api/v1/projects/735b014f-f9ff-4974-9c80-c703157de421/2839810/badge.svg)](https://semaphoreci.com/calico/operator)
[![Docker image](https://img.shields.io/badge/docker-quay.io%2Ftigera%2Foperator-blue)](https://quay.io/repository/tigera/operator)

This repository contains a Kubernetes operator which manages the lifecycle of a Calico or Tigera Secure installation on Kubernetes or OpenShift. Its goal is
to make installation, upgrades, and ongoing lifecycle management of Calico and Tigera Secure as simple and reliable as possible.

This operator is built using the [operator-sdk](https://github.com/operator-framework/operator-sdk), so you should be familiar with how that works before getting started.

## Get Started Developing

### Code structure

There are a few important areas to be aware of:

- Operator API definitions exist in `pkg/apis/operator/v1`
- Rendering code for generating Kubernetes resources is in `pkg/render`
- Control/reconcile loops for each component can be found in `pkg/controller/<component>`
- Status reporting is in `pkg/controller/status`

Tests:

- Tests for file `X.go` can be found in `X_test.go`.
- FV tests which run against a local cluster can be found in `test/*.go`.

### Design principles

When developing in the operator, there are a few design principles to be aware of.

- API changes should be rare occurences, and the API should contain as little as possible. Use auto-detection
  or automation wherever possible to reduce the API surface.
- Each "component" should receive its own CRD, namespace, controller, and status manager. e.g., compliance, networking, apiserver.
- Controllers interact with each other through the Kubernetes API. For example, by updating status on relevant objects.

### Adding a new CRD

New APIs are added using the `operator-sdk` tool.

```
operator-sdk add api --api-version=operator.tigera.io/v1 --kind=<Kind>
```

When modifying or adding CRDs, you will need to run `make gen-files` to update the auto-generated files. The tool
might change the scope of existing resources to "Namespaced", so make sure to set them back to their desired state.

### Adding a new controller

New controllers are also added using the `operator-sdk` tool.

```
operator-sdk add controller --api-version=operator.tigera.io/v1 --kind=<Kind>
```

You will need to modify the auto-generated controller's `Add` function to accept additional arguments
in order to match the AddToManagerFuncs defined in [pkg/controller/controller.go](./pkg/controller/controller.go).

### Running it locally

You can create a local k3d cluster with the Makefile:

	make cluster-create

Then, run the operator against the local cluster:

	KUBECONFIG=./kubeconfig.yaml go run ./cmd/manager

To launch Calico, install the default custom resource:

	kubectl create -f ./deploy/crds/operator_v1_installation_cr.yaml

To tear down the cluster:

	make cluster-destroy

### Using Tigera Secure

To install Tigera Secure instead of Calico, you need to install an image pull secret,
as well as modify the Installation CR.

Create the pull secret in the tigera-operator namespace:

```
kubectl create secret -n tigera-operator generic tigera-pull-secret \
    --from-file=.dockerconfigjson=<PATH/TO/PULL/SECRET> \
    --type=kubernetes.io/dockerconfigjson
```

Then, modify the installation CR (e.g., with `kubectl edit installations`) to include the following:

```
spec:
  variant: TigeraSecureEnterprise
  imagePullSecrets:
  - tigera-pull-secret
```

You can then install additional Tigera Secure components by creating their CRs from within
the `./deploy/crds/` directory.

### Running unit tests

To run all the unit tests, run:

	make test

To run a specific test or set of tests, use the `GINKGO_FOCUS` argument.

	make test GINKGO_FOCUS="component function tests"
