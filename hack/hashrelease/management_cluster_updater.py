#!/usr/bin/python3
#
#/ Usage: python3 update_hashrelease_cluster.py --clusterId [clusterId] --imageTag [operatorCloudImageTag]  --hashReleaseUrl [hashReleaseUrl]
#
#/ Prerequisite 1: you must have an operator-cloud image built, tagged and pushed based on the upstream hashrelease
#/ Prerequisite 2: you must have a running calico cloud management cluster monitored in ArgoCD

import argparse
import logging
import subprocess
import os
import sys

import requests
import ruamel.yaml

class ManagementClusterUpdater:
  """
  A class that handles updating the management cluster to a specified hashrelease. This script only is used for single-tenant management clusters.

  Attributes:
      clusterId (str): The management cluster id be to updated.
      imageTag (str): The operator cloud image tag to use.
      hashReleaseUrl (str): The url of the enterprise hashrelease.
  """
  ENV=os.environ
  ARGOCD_DEV_URL="argocd.dev.calicocloud.io"
  ARGOCD="argocd"
  ARGOCD_SYNC_TIMEOUT=os.getenv("ARGOCD_SYNC_TIMEOUT", 900) # 15 minutes

  logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

  def __init__(self, clusterId: str, imageTag: str, hashReleaseUrl: str):
    
    if not imageTag:
      logging.error(f"Image tag not defined, please specify an operator-cloud image tag")
      raise AttributeError(f"Image tag not defined, please specify an operator-cloud image tag")

    if not clusterId:
      alternateClusterId = os.getenv("CLUSTER_ID", "yjefe7y1") # Long-lived bleeding edge (hashrelease) cluster ID
      if not alternateClusterId:
        logging.error(f"Cluster ID is not defined, please specify the cluster ID")
        raise AttributeError(f"Cluster ID not defined, please specify the cluster ID")
      else:
        logging.info(f"Using alternate clusterId value ({alternateClusterId}) set from the env var")
        clusterId = alternateClusterId
        
    if not hashReleaseUrl:
      logging.error(f"Hashrelease URL is not defined, please specify the url")
      raise AttributeError(f"Hashrelease URL is not defined, please specify the url")
    
    self.clusterId = clusterId.strip()
    self.imageTag = imageTag.strip()
    self.hashReleaseUrl = hashReleaseUrl.strip().rstrip('/') # Remove whitespace and leading slashes

  def update_management_cluster(self):
    try:
      logging.info(f"Updating the hashrelease cluster given the following parameters:")
      logging.info(f"clusterId: {self.clusterId}")
      logging.info(f"operatorCloudImageTag: {self.imageTag}")
      logging.info(f"hashReleaseUrl: {self.hashReleaseUrl}")
      
      logging.info(f"Disabling automatic sync for {self.clusterId}-management-calient")
      self.run_command_with_output(f"{self.ARGOCD} app set {self.clusterId}-management-calient --source-position 1 --sync-policy none --server {self.ARGOCD_DEV_URL}")

      logging.info(f"Disabling alert manager on {self.clusterId}-management-monitoring app to eliminate alert noise")
      self.run_command_with_output(f"{self.ARGOCD} app set {self.clusterId}-management-monitoring --parameter alertmanager.enabled=false --server {self.ARGOCD_DEV_URL}")

      logging.info(f"Updating tigera-operator version in the {self.clusterId}-management cluster to use image tag {self.imageTag}")
      self.run_command_with_output(f"{self.ARGOCD} app set {self.clusterId}-management-calient --source-position 1 --parameter tigeraOperator.version={self.imageTag} --server {self.ARGOCD_DEV_URL}")

      revision = self.get_revision_from_hashrelease_url(self.hashReleaseUrl)
      logging.info(f"Updating the tigera-operator helm chart target revision to {revision}")
      self.run_command_with_output(f"{self.ARGOCD} app set {self.clusterId}-management-calient --source-position 1 --revision {revision} --server {self.ARGOCD_DEV_URL}")

      logging.info(f"Updating the tigera-operator CRDs helm chart target revision to {revision}")
      self.run_command_with_output(f"{self.ARGOCD} app set {self.clusterId}-management-calient --source-position 2 --revision {revision} --server {self.ARGOCD_DEV_URL}")

      logging.info(f"Re-enabling automatic sync for {self.clusterId}-management-calient")
      self.run_command_with_output(f"{self.ARGOCD} app set {self.clusterId}-management-calient --source-position 1 --sync-policy auto --self-heal --server {self.ARGOCD_DEV_URL}")

    except Exception as e:
      logging.error(f"Failed to update the {self.clusterId}-management cluster to use operator cloud image tag '{self.imageTag}' on revision '{self.revision}' via ArgoCD CLI. Output: {e.output}")
      sys.exit(1)

  def run_healthchecks(self):
    try:
      self.run_command_with_output(f"{self.ARGOCD} app wait {self.clusterId}-management-calient --health --sync --timeout {self.ARGOCD_SYNC_TIMEOUT} --server {self.ARGOCD_DEV_URL}")
    except Exception as e:
      logging.error(f"ArgoCD app {self.clusterId}-management-calient failed to sync after {self.ARGOCD_SYNC_TIMEOUT} seconds. Output: {e.output}")
      sys.exit(1)

  def run_command_with_output(self, cmd):
    try:
      result = subprocess.check_output(cmd, shell=True, env=self.ENV).decode(sys.stdout.encoding).strip()
      logging.info(f"'{cmd}' executed successfully! Output: {result}")
    except subprocess.CalledProcessError as e:
      logging.error(f"Failed to run command: '{cmd}'. Error: {e}")
      sys.exit(1)

    return result
  
  def get_revision_from_hashrelease_url(self, url: str):
      try:
        yaml = ruamel.yaml.YAML()
        # Retrieve revision from upstream hashrelease pinned_versions.yml file.
        response = requests.get(f"{url}/pinned_versions.yml", allow_redirects=True)
        pinnedVersionsYaml = response.content.decode("utf-8")
        pinnedVersions = yaml.load(pinnedVersionsYaml)
        revision = f"{pinnedVersions[0]['title']}"
        logging.info(f"Target revision value for {url} is {revision}")
        return revision
      except Exception as e:
        logging.error(f"Failed to get revision from {url}. Output: {e}")
        sys.exit(1)
  
def main():
  parser = argparse.ArgumentParser(description="Updates the management cluster to a specified hashrelease via ArgoCD")

  parser.add_argument(
      "--clusterId",
      type=str,
      required=True,
      help="The id of the cluster to update. Defaults to the bleeding edge hashrelease cluster ID if not overridden in env vars. eg. yjefe7y1"
  )

  parser.add_argument(
      "--imageTag",
      type=str,
      required=True,
      help="The operator cloud image tag name to use for updating the hashrelease cluster.",
  )

  parser.add_argument(
      "--hashReleaseUrl",
      type=str,
      required=True,
      help="The url of the enterprise hashrelease. eg. https://2023-09-12-v3-18-turkey.docs.eng.tigera.net"
  )
  args = parser.parse_args()
  mgmtClusterUpdater = ManagementClusterUpdater(args.clusterId, args.imageTag, args.hashReleaseUrl)
  mgmtClusterUpdater.update_management_cluster()
  mgmtClusterUpdater.run_healthchecks()

if __name__ == "__main__":
  main()
