#!/bin/bash

if [ "$OPENSHIFT" != "true" ]; then
  echo "Not in Openshift, so do not try to update Security Groups"
  exit 0
fi

## We need to use the apiserver address the kubelet uses since the
# apiserver service IP won't be available yet.
# Use the mounted in kubeconfig for the kubelet to get the apiserver.
export KUBECONFIG=$KUBELET_KUBECONFIG
apiserver_url=$(kubectl config view -o jsonpath='{.clusters[0].cluster.server}')
if [ $? -ne 0 ]; then
  echo "Failed to get apiserver from mounted kubeconfig"
  echo "$apiserver_url"
  echo "Kubelet kubeconfig:"
  cat $kubelet_kcfg
  exit 1
fi
unset KUBECONFIG
export KUBERNETES_SERVICE_HOST=$(echo $apiserver_url | sed -e 's|^.*://\(.*\):.*$|\1|')
echo "Using kubernetes host $KUBERNETES_SERVICE_HOST"
export KUBERNETES_SERVICE_PORT=$(echo $apiserver_url | sed -e "s|^.*${KUBERNETES_SERVICE_HOST}\(:[0-9]*\)\{0,1\}.*$|\1|" | tr -d ':')
echo "Using kubernetes host $KUBERNETES_SERVICE_PORT"


## Collect the AWS credentials from the secret in the kube-system and
# then export them for use the in security group setup

# Collect the credential in json format
creds=$(kubectl get secret -n kube-system aws-creds -o json)
if [ $? -ne 0 ]; then
  echo "No AWS credentials in kube-system namespace, need to retry initializing security groups."
  echo "$creds"
  if [ "$REQUIRE_AWS" == "true" ]; then
    exit 1
  else
    exit 0
  fi
fi

# Parse out the key id and then decode it
encoded_key_id=$(echo $creds | jq --raw-output '.data.aws_access_key_id')
if [ $? -ne 0 ]; then
  echo "Failed to parse key id from aws-creds.data.aws_access_key_id: $encoded_key_id"
  exit 1
fi
key_id=$(echo $encoded_key_id  | base64 --decode)
if [ $? -ne 0 ]; then
  echo "Failed to decode key id from aws-creds.data.aws_access_key_id: $key_id"
  exit 1
fi
export AWS_ACCESS_KEY_ID=$key_id

# Parse out the key and then decode it
encoded_key=$(echo $creds | jq --raw-output '.data.aws_secret_access_key')
if [ $? -ne 0 ]; then
  echo "Failed to parse key from aws-creds.data.aws_secret_access_key: $encoded_key"
  exit 1
fi
key=$(echo $encoded_key | base64 --decode)
if [ $? -ne 0 ]; then
  echo "Failed to decode key from aws-creds.data.aws_secret_access_key: $key"
  exit 1
fi
export AWS_SECRET_ACCESS_KEY=$key

# Grab the availability-zone from the AWS metadata and then cut it down the the
# region.
export AWS_DEFAULT_REGION=$(curl --silent http://169.254.169.254/latest/meta-data/placement/availability-zone | sed -e 's/^\(.*[0-9]\)[a-z]*/\1/')

/aws-setup-security-groups.sh
