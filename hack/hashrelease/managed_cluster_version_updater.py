#!/usr/bin/python3
#
#/ Usage: python3 managed_cluster_version_updater.py --hashReleaseUrl [hashReleaseUrl]
#
#/ Prerequisite 1: Must have checked out the helm-charts repo
#/ Prerequisite 2: Banzai-service changes that consume new hashrelease is merged to master/dev environment

import argparse
import logging
import subprocess
import os
import sys
import time
import ruamel.yaml

# in-place YAML modifier
yaml = ruamel.yaml.YAML()

class ManagedClusterVersionUpdater:
  """
  A class that will update the managed cluster versions file to use a specified hashrelease.

  Attributes:
      hashReleaseURL (str): The hashrelease URL to update the managed cluster versions helm chart.
      managedVersionsFilePath (str): The file path to the managed versions values file.
  """
  ENV=os.environ
  MANAGED_VERSION_ENTRY_NAME=os.getenv("MANAGED_VERSION_ENTRY_NAME", "bleeding-edge") #  Default value will update an versions entry called "bleeding-edge"
  logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

  def __init__(self, hashReleaseUrl: str):
    if not hashReleaseUrl:
      logging.error(f"Hash Release URL is not defined, please specify the hashrelease URL")
      raise AttributeError(f"Hash Release URL is not defined, please specify the hashrelease URL")

    self.managedVersionsFilePath = os.getenv("MANAGED_VERSIONS_FILE_PATH", f"{os.getcwd()}/helm-charts/charts/tds-apiserver/values.yaml")
    if not os.path.exists(f"{self.managedVersionsFilePath}"):
      logging.error(f"Managed versions file path is not defined, please specify the path to the managed versions file")
      raise AttributeError(f"Managed versions file path is not defined, please specify the path to the managed versions file")
    
    self.hashReleaseURL = hashReleaseUrl.strip().rstrip('/') # Remove whitespace and leading slashes

  def update_managed_cluster_version_helm_charts(self):
    try:
      with open(self.managedVersionsFilePath, "r") as managed_versions_file:
        managedVersionsYaml = yaml.load(managed_versions_file)
        versionsList = managedVersionsYaml.get("managedClusterVersions", {}).get("versions", [])
        bleedingEdgeVersionFound = False

        for version_entry in versionsList:
          # Partial string match for bleeding-edge version
          if self.MANAGED_VERSION_ENTRY_NAME in version_entry["version"]:
            logging.info(f"Found {self.MANAGED_VERSION_ENTRY_NAME} entry")
            bleedingEdgeVersionFound = True
            if self.hashReleaseURL != version_entry["enterpriseDownloadUrl"]:
              logging.info(f"Updating {self.MANAGED_VERSION_ENTRY_NAME} version enterpriseDownloadUrl entry in values.yaml from '{version_entry['enterpriseDownloadUrl']}'  to '{self.hashReleaseURL}'") 
              version_entry["enterpriseDownloadUrl"] = self.hashReleaseURL
              with open(self.managedVersionsFilePath, "w") as updated_managed_versions_file:
                yaml.dump(managedVersionsYaml, updated_managed_versions_file)
              # Create a PR whenever there's a change in hashrelease url
              self.create_helm_charts_pr()
            else:
              logging.info(f"The managed cluster version for the bleeding edge cluster is already set to {self.hashReleaseURL}, not updating tds-apiserver values and PR")
            break
        
        if not bleedingEdgeVersionFound:
          logging.error(f" Did not find a managed version entry in tds-apiserver values.yaml called {self.MANAGED_VERSION_ENTRY_NAME}")
          sys.exit(1)

    except FileNotFoundError:
      logging.error(f"Managed cluster versions file not found. Tried to look in path: {self.managedVersionsFilePath}")
      sys.exit(1)
    except ruamel.yaml.YAMLError as e:
      logging.error(f"Error parsing YAML file at {self.managedVersionsFilePath}: Error: {e}")
      sys.exit(1)
    except SystemExit as e:
      logging.error(f'System Exit occured. Error: {e}')
      sys.exit(1)
    except Exception as e:
      logging.error(f"Failed to update helm-charts repo to use hashrelease '{self.hashReleaseUrl}'. Error: {e}")
      sys.exit(1)

  def create_helm_charts_pr(self):
    logging.info(f"Creating helm-charts PR with new managed version hashrelease updates")
    branch = "update-tds-helm-values"
    prTitle = "[Hashrelease Automation] Update dev tds-apiserver values.yaml"
    message = f"Update dev tds-apiserver values.yaml to use the hashrelease: {self.hashReleaseURL}"

    self.run_command_with_output(f"git checkout -B {branch}")
    self.run_command_with_output(f"git commit -a -m '{message}'")
    self.run_command_with_output(f"git push origin -u {branch}")
    current_branch = self.run_command_with_output(f"git branch --show-current")
    prUrl = self.run_command_with_output(f"gh pr create --title '{prTitle}' --body '{message}' --label 'automerge' --head '{current_branch}'")

    # Wait for 30 minutes to see if the PR has been merged by the CI, if it has not then most likely it failed
    timeoutSeconds = 30 * 60
    startTime = time.time()
    prMergedQueryCommand = f"gh pr view {prUrl} --json mergedAt | jq .mergedAt"
    prMerged = self.run_command_with_output(prMergedQueryCommand)
    while prMerged == "null":
      logging.info("Watching every 30s for merged status")
      logging.info(f"PR State: {prMerged}")
      time.sleep(30)
      prMerged = self.run_command_with_output(prMergedQueryCommand)
      if time.time() - startTime >= timeoutSeconds:
        logging.error(f"Timed out after 30 minutes waiting for PR {prUrl} to be merged")
        sys.exit(1)

  def run_command_with_output(self, cmd):
    try:
      result = subprocess.check_output(cmd, shell=True, env=self.ENV).decode(sys.stdout.encoding).strip()
      logging.info(f"'{cmd}' executed successfully! Output: {result}")
    except subprocess.CalledProcessError as e:
      logging.error(f"Failed to run command: '{cmd}'. Error: {e}")
      sys.exit(1)

    return result
      
def main():
  parser = argparse.ArgumentParser(description="Creates a PR to the helm-charts repo to update the EE hashrelease URL")

  parser.add_argument(
      "--hashReleaseUrl",
      type=str,
      required=True,
      help="The url of the enterprise hashrelease. eg. https://2023-09-12-v3-18-turkey.docs.eng.tigera.net"
  )

  args = parser.parse_args()
  managedClusterUpdater = ManagedClusterVersionUpdater(args.hashReleaseUrl)
  managedClusterUpdater.update_managed_cluster_version_helm_charts()

if __name__ == "__main__":
  main()


