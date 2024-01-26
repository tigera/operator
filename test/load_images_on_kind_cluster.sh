#!/bin/bash

function load_image() {
    local node=${1}
    for IMAGETAR in ${@:2}
    do
      docker cp ./${IMAGETAR} ${node}:/${IMAGETAR}
      docker exec -t ${node} ctr -n=k8s.io images import /${IMAGETAR}
      docker exec -t ${node} rm /${IMAGETAR}
    done
}

KIND_NODES="kind-control-plane kind-worker kind-worker2 kind-worker3"

for NODE in ${KIND_NODES}
do
  load_image ${NODE} ${@:2}
done
