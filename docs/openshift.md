# Installing Calico on OpenShift v4

Note: These steps are experimental with a number of known issues. The installed cluster is not fully functional, nor is it production ready, and is intended for development and testing purposes.

## Prerequisites

1. These instructions assume you have created an [Red Hat account](https://docs.openshift.com/container-platform/4.1/welcome/index.html)
1. These instructions require OpenShift v4.1.3 or later.
1. Your host network must allow the required BGP and IP-in-IP traffic for Calico / Tigera Secure EE (if using installer-provisioned infrastructure, this is automated in AWS security groups).

## Create an appropriate install-config.yaml

1. Create an install-config.yaml file. See the [RedHat documentation](https://docs.openshift.com/container-platform/4.1/welcome/index.html) for more information.

   ```
   openshift-install create install-config
   ```

1. Edit the generated config file to disable OpenShiftSDN for networking

   ```
   sed -i  's/OpenShiftSDN/Calico/' install-config.yaml
   ```

## Generate manifests to use

1. Now, populate the manifests directory based on the config. The following command will create a directory called
   `manifests` which will be consumed as part of the installation.

   ```
   openshift-install create manifests
   ```

1. Once complete, add in the Tigera operator manifests from the deploy directory. Run the following
   command from the root of this repository:

   ```
   cp deploy/openshift/calico/* manifests
   ```

## Create the cluster

The steps here may vary based on platform and installation type. See the RedHat documentation for detailed installation steps for both
user-provisioned infrastructure (UPI) as well as installer provisioned infrastructure (IPI).

- RedHat documentation for [user-provisioned infrastructure (bare-metal)](https://docs.openshift.com/container-platform/4.1/installing/installing_bare_metal/installing-bare-metal.html)
- RedHat documentation for [user-provisioned infrastructure (vSphere)](https://docs.openshift.com/container-platform/4.1/installing/installing_vsphere/installing-vsphere.html)

### Example: Installing using IPI on AWS

1. Start the cluster creation.

   ```
   openshift-install create cluster
   ```

   This will take a while, and due to some current limitations in OpenShift will require some manual steps to keep the process
   unblocked. Wait for the following output to appear:

   ```
   INFO Consuming "Openshift Manifests" from target directory
   INFO Consuming "Worker Machines" from target directory
   INFO Consuming "Common Manifests" from target directory
   INFO Consuming "Master Machines" from target directory
   INFO Creating infrastructure resources...
   INFO Waiting up to 30m0s for the Kubernetes API at https://api.casey-ocp.openshift.crc.aws.eng.tigera.net:6443...
   ```

1. You should then eventually see all cluster operators become ready.

   ```
   oc get clusteroperator
   ```
