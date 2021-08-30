#!/bin/bash -e

# kubectl binary.
: ${kubectl:=./kubectl}

# kind binary.
: ${KIND:=./kind}

# Set config variables needed for ${kubectl}.
export KUBECONFIG=~/.kube/kind-config-kind

function checkModule(){
  MODULE="$1"
  echo "Checking kernel module $MODULE ..."
  if lsmod | grep "$MODULE" &> /dev/null ; then
    return 0
  else
    return 1
  fi
}

echo "kubernetes dualstack requires ipvs mode kube-proxy for the moment."
MODULES=("ip_vs" "ip_vs_rr" "ip_vs_wrr" "ip_vs_sh" "nf_conntrack_ipv4")
for m in "${MODULES[@]}"; do
  checkModule $m || {
      echo "Could not find kernel module $m. install it..."
      # Modules could be built into kernel and not exist as a kernel module anymore.
      # For instance, kernel 5.0.0 ubuntu has nf_conntrack_ipv4 built in.
      # So try to install modules required and continue if it failed..
      sudo modprobe $m || true
  }
done
echo

echo "Download kind executable with dual stack support"
# We need to replace kind executable and node image
# with official release once dual stack is fully supported by upstream.
curl -L https://github.com/song-jiang/kind/releases/download/dualstack-1.17.0/kind -o ${KIND}
chmod +x ${KIND}

echo "Create kind cluster"
${KIND} create cluster --image songtjiang/kindnode-dualstack:1.17.0 --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "192.168.0.0/16,fd00:10:244::/64"
  ipFamily: DualStack
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
  featureGates:
    IPv6DualStack: true
- |
  apiVersion: kubeproxy.config.k8s.io/v1alpha1
  kind: KubeProxyConfiguration
  metadata:
    name: config
  mode: ipvs
  conntrack:
    maxPerCore: 0
EOF

${kubectl} get no -o wide
${kubectl} get po --all-namespaces -o wide

echo "Set ipv6 address on each node"
docker exec kind-control-plane ip -6 a a 2001:20::8/64 dev eth0
docker exec kind-worker ip -6 a a 2001:20::1/64 dev eth0
docker exec kind-worker2 ip -6 a a 2001:20::2/64 dev eth0
echo

echo "dual stack kind cluster is ready without network plugin"
echo "export KUBECONFIG=~/.kube/kind-config-kind to access cluster."
