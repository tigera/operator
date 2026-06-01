### Adding a new CRD

New APIs are added using the `operator-sdk` tool.

```
operator-sdk create api --group=operator.tigera.io --version=v1 --kind=<Kind> --resource --namespaced=false
```

When modifying or adding CRDs, you will need to run `make gen-files` to update the auto-generated files. The tool
might change the scope of existing resources to "Namespaced", so make sure to set them back to their desired state.

See this demo pull request for more detail on adding both a controller and CRD: https://github.com/tigera/operator/pull/3587

### Adding a new controller

New controllers are also added using the `operator-sdk` tool.

```
operator-sdk create api --group=operator.tigera.io --version=v1 --kind=<Kind> --controller
```

New controllers will be created in the newer format so it should be considered if it is desirable to keep the
current format that calls to a controller in `pkg/controller` or add the controller only in `controllers`.

### Running it locally

You can create a local k3d cluster with the Makefile:

	make cluster-create

Export the kubeconfig:

	export KUBECONFIG=./kubeconfig.yaml

Create the tigera-operator namespace:

	kubectl create ns tigera-operator

Then, run the operator against the local cluster:

	# enable-leader-election is necessary since you'll be running the operator outside of a cluster
	KUBECONFIG=./kubeconfig.yaml go run ./ --enable-leader-election=false

To launch Calico, install the default custom resource:

	kubectl create -f ./config/samples/operator_v1_installation.yaml

To tear down the cluster:

	make cluster-destroy

#### Running a custom image in your existing Calico (Enterprise) cluster

These steps assume that you already have installed the operator in a Calico (Enterprise) cluster after following either
docs.projectcalico.org or docs.tigera.io. To verify, run `kubectl get deployment -n tigera-operator tigera-operator`.
You should see an existing deployment.
The steps also assume that you have setup your docker such that you can push to a registry.

These are the steps:
1. Make your own code changes to this repository.
2. Create the binaries and a docker image.
   ```bash
   make image
   ```
   The output will show you the docker tag that was just created. (For example: `Successfully tagged tigera/operator:latest-amd64`.)
3. Re-tag the image and push it to a registry of your choice.
   ```
   export IMAGE=myregistry.com/user/tigera/operator:my-tag
   docker tag tigera/operator:latest $IMAGE
   docker push $IMAGE
   ```
4. Change your deployment to use the image.
   ```
   kubectl set image deploy  -n tigera-operator tigera-operator  tigera-operator=$IMAGE
   ```
   _If your image is in a private registry, you also need to add [imagePullSecrets](https://kubernetes.io/docs/concepts/containers/images/) to the deployment._

#### Set breakpoints in Goland IDE and run the code against your existing Calico (Enterprise) cluster

These steps assume that you already have installed the operator in a Calico (Enterprise) cluster after following either
https://docs.projectcalico.org or https://docs.tigera.io. To verify, run `kubectl get deployment -n tigera-operator tigera-operator`.
You should see an existing deployment. Install [kubefwd](https://kubefwd.com/).

1. Scale down the operator, so it does not interfere with your own:
```bash
kubectl scale deploy -n tigera-operator tigera-operator --replicas=0
```
2. Run kubefwd in a separate terminal, so pods and service names are accessible from your local computer.
```bash
kubefwd svc -n calico-system -n tigera-compliance -n tigera-kibana -n tigera-manager -n tigera-dex -n tigera-elasticsearch -n tigera-prometheus -c $KUBECONFIG
```
3. Open a code file in your editor and set a breakpoint.
4. Create a debug configuration by right-clicking main.go and select `modify run configuration`.
   1. Under Run kind, select `Package`
   2. Under Environment, add `KUBECONFIG=/path/to/config`
   3. In Program arguments, add `--enable-leader-election=false`
5. Save the configuration. You can now run it in debug mode.

### Using Calico Enterprise

To install Calico Enterprise instead of Calico, you need to install an image pull secret,
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
  variant: CalicoEnterprise
  imagePullSecrets:
  - name: tigera-pull-secret
```

You can then install additional Calico Enterprise components by creating their CRs from within
the `./deploy/crds/` directory.

### Running unit tests

To run all the unit tests, run:

	make test

To run a specific test or set of tests, use the `GINKGO_FOCUS` argument.

	make test GINKGO_FOCUS="component function tests"

### Making temporary changes to components the operator manages

The operator creates and manages resources and will reconcile them to be in the desired state. Due to the
reconciliation it does, if a user makes direct changes to a resource the operator will revert those changes.
To enable the user to make temporary changes, an annotation can be added to any resource directly managed by
the operator which will cause the operator to no longer update the resource.
Adding the following as an annotation to any resource will prevent the operator from making any future updates to the annotated resource:

  *Do not use this unless you are a developer working on the operator. If you add this annotation,
  you must remove it before the operator can manage the resource again.*

  ```
  unsupported.operator.tigera.io/ignore: "true"
  ```

#### Example update to calico-node DaemonSet

Notice that the annotation is added in the top level metadata (not in the spec.template.metadata).
(note the below is not a valid manifest but just an example)
```
kind: DaemonSet
apiVersion: apps/v1
metadata:
  name: calico-node
  namespace: calico-system
  labels:
    k8s-app: calico-node
  annotations:
    # You should NOT use this unless you want to block the operator from doing its job managing this resource.
    unsupported.operator.tigera.io/ignore: "true"
spec:
  template:
    metadata:
      labels:
        k8s-app: calico-node
      annotations:
        scheduler.alpha.kubernetes.io/critical-pod: ''
    spec:
      containers:
        - name: calico-node
          image: calico/node:my-special-tag
```

### Updating the bundled version of Envoy Gateway

The Envoy Gateway version pin and the source-built images all live in
`projectcalico/calico` (`third_party/envoy-{gateway,proxy,ratelimit}`). The
operator embeds the upstream `gateway-helm` chart — fetched at build time and
rendered at runtime via the Helm SDK — and pins `go.mod`'s
`github.com/envoyproxy/gateway` (the chart decoder types) to the same version.
`make gen-versions` copies that single version pin out of a calico clone into
`go.mod`; the operator Makefile then derives `ENVOY_GATEWAY_VERSION` from
`go.mod`, so the embedded chart and the decoder types can never drift. A version
bump therefore lands in two PRs — calico first, operator second.

**In `projectcalico/calico`:**

1. Bump `ENVOY_GATEWAY_VERSION` in `third_party/envoy-gateway/Makefile`. (Renovate
   normally does this automatically — see `renovate.json`.) Note that Renovate
   only handles envoy-gateway *patch* bumps; it does not touch the matching
   envoy-proxy/envoy-ratelimit versions or refresh the patch stacks, so
   minor/major bumps still need the next steps by hand.

1. Update `third_party/envoy-proxy/Makefile` and
   `third_party/envoy-ratelimit/Makefile` to the matching `proxy` and
   `ratelimit` versions. Versions are listed in the Envoy Gateway release notes
   ([for example](https://github.com/envoyproxy/gateway/releases/tag/v1.3.2))
   and the [compatibility matrix](https://gateway.envoyproxy.io/news/releases/matrix/).

1. For each of `third_party/envoy-{gateway,proxy,ratelimit}`: review whether
   existing patches still apply cleanly and remain required; update or drop
   them as needed.

1. Commit and post as a `projectcalico/calico` PR.

**In `tigera/operator` (after the calico PR merges):**

> **Normally you don't run these by hand.** The hourly `sync-versions` workflow
> (`.github/workflows/sync-versions.yml`) runs `make gen-versions`, so within ~an hour of the calico PR
> merging an **"Auto: sync versions"** PR appears with the `go.mod` envoy-gateway
> pin already applied (step 1); CI on that PR rebuilds the embedded chart from the
> pin (the `.tgz` is gitignored and a build prerequisite, so step 2 is
> local-only). Run the steps below by hand only for an out-of-cycle bump. 
> The parts the sync **can't** do are
> the `gateway_api.go` changes for new CRD kinds (step 3) and any test fixes
> (step 4) — those show up as red CI on the auto-sync PR.

1. Run `make gen-versions`. The `update-envoy-gateway-version` target it invokes
   reads calico's `ENVOY_GATEWAY_VERSION` pin and, when it differs from `go.mod`,
   runs `go mod edit -require=github.com/envoyproxy/gateway@<new> && go mod tidy`
   to pin the Go decoder types. If `go mod tidy` surfaces other changes (e.g. a
   `GO_BUILD_VER` bump), address them.

1. Delete `pkg/render/gatewayapi/gateway-helm.tgz` and run `make build`. This
   re-downloads the chart at the version now pinned in `go.mod` (the Makefile
   derives `ENVOY_GATEWAY_VERSION` from it), embeds it in the operator binary,
   and renders it at runtime using the Helm SDK.

1. If the chart introduced new CRDs or resource kinds, update
   `pkg/render/gatewayapi/gateway_api.go` to parse them.

1. Run `make ut`, address issues.

1. Commit and post as a `tigera/operator` PR.
