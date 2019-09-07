#!/bin/bash

# This file is based on
#  https://github.com/openshift/cluster-network-operator/blob/master/hack/open-ovn-ports.sh

set -o nounset

function get_vpc_id() {
    local mac=$(curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/ | head -n 1)
    local vpc_id=$(curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/$mac/vpc-id)
    echo $vpc_id
}

function get_group_id() {
    local vpc_id="$1"
    local name="$2"

    id=$(aws ec2 describe-security-groups --filters "Name=tag:Name,Values=${name}" "Name=vpc-id,Values=$vpc_id" | \
            jq -r .SecurityGroups[0].GroupId)
    if [ $? -ne 0 ]; then
        echo "error: describing security groups"
        exit 1
    fi
    if [[ "${id}" == "null" ]]; then
        echo "error: security group '${name}' does not (yet?) exist" 1>&2
        exit 1
    fi
    echo "${id}"
}

function open_port() {
    src_group="$1"
    dest_group="$2"
    protocol="$3"
    port="$4"

    out="$(aws ec2 authorize-security-group-ingress --group-id "${dest_group}" \
        --source-group "${src_group}" --protocol "${protocol}" --port "${port}" 2>&1)"
    if [ $? -ne 0 ]; then
        if [[ $out =~ InvalidPermission.Duplicate ]]; then
            # If the rule already exists just return success
            echo "$out"
            echo "Rule already exists for src $src_group, dst $dest_group, proto $protocol, port $port"
            return 0
        fi
        echo "error: $out"
        exit 1
    fi
}

vpc=$(get_vpc_id)
masters=$(get_group_id $vpc "*-master-sg")
workers=$(get_group_id $vpc "*-worker-sg")

# Add rules to master SG that allow incoming from master and worker for BGP and IPIP
# The below is IPIP, BGP, and, Typha comms. The -1 for the port is for all ports.
open_port "${masters}" "${masters}" tcp 179
open_port "${masters}" "${masters}" 4 -1
open_port "${masters}" "${masters}" tcp 5473
open_port "${workers}" "${masters}" tcp 179
open_port "${workers}" "${masters}" 4 -1
open_port "${workers}" "${masters}" tcp 5473

# Add rules to worker SG that allow incoming from master and worker for BGP and IPIP
# The below is IPIP, BGP, and, Typha comms. The -1 for the port is for all ports.
open_port "${masters}" "${workers}" tcp 179
open_port "${masters}" "${workers}" 4 -1
open_port "${masters}" "${workers}" tcp 5473
open_port "${workers}" "${workers}" tcp 179
open_port "${workers}" "${workers}" 4 -1
open_port "${workers}" "${workers}" tcp 5473
