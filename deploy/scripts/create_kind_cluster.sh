#!/bin/bash -e

# kubectl binary.
: ${kubectl:=./kubectl}

# kind binary.
: ${KIND:=./kind}

# Set config variables needed for ${kubectl}.
export KUBECONFIG=~/.kube/kind-config-kind

echo "Download kind executable"
curl -L https://github.com/kubernetes-sigs/kind/releases/download/v0.10.0/kind-linux-amd64 -o ${KIND}
chmod +x ${KIND}

echo "Create kind cluster"
${KIND} create cluster --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "192.168.0.0/16"
  ipFamily: ipv4
nodes:
# the control plane node
- role: control-plane
- role: worker
- role: worker
kubeadmConfigPatches:
- |
  apiVersion: kubeadm.k8s.io/v1beta2
  kind: ClusterConfiguration
  metadata:
    name: config
- |
  apiVersion: kubeproxy.config.k8s.io/v1alpha1
  kind: KubeProxyConfiguration
  metadata:
    name: config
  mode: ipvs
EOF

${kubectl} get no -o wide
${kubectl} get po --all-namespaces -o wide

echo "kind cluster is ready without network plugin"
echo "export KUBECONFIG=~/.kube/kind-config-kind to access cluster."
