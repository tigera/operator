#!/bin/bash -e

# kind binary.
: ${KIND:=./kind}

config=~/.kube/kind-config-kind

if [ ! -f ${config} ]; then
  echo no kind cluster found. 
  exit 0
fi

if [ ! -f ${KIND} ]; then
  echo can not find ${KIND}, cluster may not exits.
  exit 0
fi

${KIND} delete cluster
rm ${KIND}
