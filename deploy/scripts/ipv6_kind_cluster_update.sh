#!/bin/bash -e

# test directory.
TEST_DIR=./tests/k8st

# kubectl binary.
: ${kubectl:=./bin/kubectl}

# kind binary.
: ${KIND:=./bin/kind}

function checkModule(){
  MODULE="$1"
  echo "Checking kernel module $MODULE ..."
  if lsmod | grep "$MODULE" &> /dev/null ; then
    return 0
  else
    return 1
  fi
}

echo "Set ipv6 address on each node"
docker exec kind-control-plane ip -6 a a 2001:20::8/64 dev eth0
docker exec kind-worker ip -6 a a 2001:20::1/64 dev eth0
docker exec kind-worker2 ip -6 a a 2001:20::2/64 dev eth0
docker exec kind-worker3 ip -6 a a 2001:20::3/64 dev eth0
echo
