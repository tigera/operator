#!/usr/bin/env python3
#
#/ Usage: python3 mt-management-cluster-updater.py --hashReleaseUrl [hashReleaseURL] --imageTag [imageTag]
#
#/ Prerequisite 1: Must have checked out the helm-charts repo

"""
Script to update multi-tenant management cluster with hashrelease versions.

This script:
1. Creates a new branch from bleeding-edge in the helm-charts repo
2. Updates tigera-operator dependency versions in Chart.yaml files
3. Updates the operator-cloud image version in values files
4. Creates a PR to merge changes back to bleeding-edge
5. Monitors CI status and waits for completion
"""

import argparse
import logging
import subprocess
import sys
import os
import time
import ruamel.yaml
import requests

# in-place YAML modifier
yaml = ruamel.yaml.YAML()


class MultiTenantClusterUpdater:
    """
    A class that handles updating the multi-tenant management cluster charts with hashrelease versions and image tags.

    Attributes:
        hashReleaseUrl (str): The url of the enterprise hashrelease.
        imageTag (str): The operator-cloud image tag to update in values files.
        chartVersion (str): The tigera-operator hashrelease helm chart version (automatically fetched 
                           from the hashrelease pinned_components.yml file).
    """
    ENV = os.environ
    BLEEDING_EDGE_BRANCH_NAME = "bleeding-edge"
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def __init__(self, hashReleaseUrl: str, imageTag: str):
        
        if not hashReleaseUrl:
            logging.error("Hashrelease URL is not defined, please specify the url")
            raise AttributeError("Hashrelease URL is not defined, please specify the url")

        if not imageTag or not imageTag.strip():
            logging.error("Image tag is empty, please specify a valid operator-cloud image tag")
            raise AttributeError("Image tag is empty, please specify a valid operator-cloud image tag")
                
        self.hashReleaseUrl = hashReleaseUrl.strip().rstrip('/')  # Remove whitespace and trailing slashes
        self.imageTag = imageTag.strip()
        
        # Always fetch chart version from hashrelease
        logging.info("Fetching chart version from hashrelease pinned_components.yml")
        self.chartVersion = self.get_chart_version_from_hashrelease()
        
        # Define charts to update
        self.charts_to_update = [
            ("charts/tigera-operator-multi-tenant-crds/Chart.yaml", "multi-tenant-crds"),
            ("charts/tigera-operator/Chart.yaml", "tigera-operator"),
            ("charts/tigera-prometheus-operator/Chart.yaml", "tigera-prometheus-operator"),
        ]
        
        # Define values files to update with imageTag
        self.values_files_to_update = [
            "charts/tigera-operator/cloud.multi-tenant-mgmt-dev.values.yaml"
        ]

    def extract_hashrelease_name(self):
        """Extract hashrelease name from URL for branch naming."""
        # Remove https:// and .docs.eng.tigera.net
        name = self.hashReleaseUrl.replace('https://', '').replace('.docs.eng.tigera.net', '')
        return name

    def get_chart_version_from_hashrelease(self):
        """Fetch and extract chart version from pinned_components.yml file."""
        try:
            pinnedComponentsUrl = f"{self.hashReleaseUrl}/pinned_components.yml"
            logging.info(f"Fetching chart version from: {pinnedComponentsUrl}")
            
            # Download the pinned components file
            response = requests.get(pinnedComponentsUrl)
            response.raise_for_status()
            
            # Parse YAML content
            data = yaml.load(response.text)
            
            # Extract title field as chart version
            chart_version = data.get('title')
            if not chart_version:
                raise ValueError("'title' field not found in pinned_components.yml")
                
            logging.info(f"Extracted chart version from hashrelease: {chart_version}")
            return chart_version
            
        except requests.RequestException as e:
            logging.error(f"Failed to fetch pinned_components.yml from {pinnedComponentsUrl}: {e}")
            raise
        except ruamel.yaml.YAMLError as e:
            logging.error(f"Error parsing YAML from {pinnedComponentsUrl}: {e}")
            raise
        except Exception as e:
            logging.error(f"Failed to extract chart version from hashrelease: {e}")
            raise

    def update_chart_dependency_version(self, file_path, dependency_name, new_version):
        """Update dependency version in a Chart.yaml file."""
        logging.info(f"Updating {file_path} - dependency {dependency_name} to version {new_version}")
        
        if not os.path.exists(file_path):
            logging.warning(f"Chart file not found: {file_path}")
            return False
            
        try:
            # Load the Chart.yaml file
            with open(file_path, 'r') as f:
                chart_data = yaml.load(f)
            
            # Find and update the dependency version
            dependencies = chart_data.get('dependencies', [])
            dependency_found = False
            updates_made = 0
            
            for dependency in dependencies:
                # Check if this dependency matches by name
                name_match = dependency.get('name') == dependency_name

                if name_match:
                    logging.info(f"Found dependency with name='{dependency_name}' on file '{file_path}'")
                    dependency_found = True
                    if dependency.get('version') != new_version:
                        old_version = dependency.get('version', 'unknown')
                        dependency['version'] = new_version
                        updates_made += 1
                        logging.info(f"Updated dependency with name='{dependency_name}' version from {old_version} to {new_version}")
                    else:
                        logging.info(f"No version change for dependency '{dependency_name}' in file '{file_path}'")
                else:
                    logging.error(f"No match for dependency '{dependency_name}' in file '{file_path}'")


            logging.info(f"Finished processing {file_path} - found={dependency_found}, updates_made={updates_made}")
            
            # Determine expected number of updates based on the chart file
            expected_updates = 2 if "charts/tigera-operator/Chart.yaml" in file_path else 1
            
            if dependency_found and updates_made == expected_updates:
                # Write the updated chart back to file
                with open(file_path, 'w') as f:
                    yaml.dump(chart_data, f)
                logging.info(f"Successfully updated {file_path} - made {updates_made} version update(s)")
                return True
            else:
                logging.warning(f"No changes made to {file_path} - expected {expected_updates} updates but made {updates_made}")
                return False
                
        except FileNotFoundError:
            logging.error(f"Chart file not found. Tried to look in path: {file_path}")
            sys.exit(1)
        except ruamel.yaml.YAMLError as e:
            logging.error(f"Error parsing YAML file at {file_path}: Error: {e}")
            sys.exit(1)
        except SystemExit as e:
            logging.error(f'System Exit occurred. Error: {e}')
            sys.exit(1)
        except Exception as e:
            logging.error(f"Failed to update chart dependency version in '{file_path}' for dependency '{dependency_name}'. Error: {e}")
            sys.exit(1)

    def update_values_file_image_version(self, file_path, new_image_tag):
        operator_cloud_image_name = "tigera-cc-dev/operator-cloud"
        """Update tigera-cc-dev/operator-cloud image version in a values YAML file."""
        logging.info(f"Updating {file_path} - {operator_cloud_image_name} image version to {new_image_tag}")

        if not os.path.exists(file_path):
            logging.warning(f"Values file not found: {file_path}")
            return False
            
        try:
            # Load the values YAML file
            with open(file_path, 'r') as f:
                values_data = yaml.load(f)
            
            # Look for the specific path: tigeraMultiTenantOperator.tigeraOperator
            operator_cloud_found = False
            updates_made = 0
            
            # Access the expected structure directly
            tigera_operator = values_data.get('tigeraMultiTenantOperator', {}).get('tigeraOperator', {})

            if tigera_operator and tigera_operator.get('image', '') == operator_cloud_image_name:
                logging.info(f"Found {operator_cloud_image_name} image configuration in tigeraMultiTenantOperator.tigeraOperator")
                operator_cloud_found = True
                
                if tigera_operator.get('version') != new_image_tag:
                    old_version = tigera_operator.get('version', 'unknown')
                    tigera_operator['version'] = new_image_tag
                    updates_made += 1
                    logging.info(f"Updated {operator_cloud_image_name} version from {old_version} to {new_image_tag}")
                else:
                    logging.info(f"No version change for {operator_cloud_image_name} image in file '{file_path}'")

            logging.info(f"Finished processing {file_path} - found={operator_cloud_found}, updates_made={updates_made}")
            if operator_cloud_found:
                # Write the updated values back to file
                with open(file_path, 'w') as f:
                    yaml.dump(values_data, f)
                logging.info(f"Successfully updated {file_path} - made {updates_made} version update(s)")
                return True
            else:
                logging.warning(f"No changes made to {file_path} - operator-cloud image version not found")
                return False
                
        except FileNotFoundError:
            logging.error(f"Values file not found. Tried to look in path: {file_path}")
            sys.exit(1)
        except ruamel.yaml.YAMLError as e:
            logging.error(f"Error parsing YAML file at {file_path}: Error: {e}")
            sys.exit(1)
        except SystemExit as e:
            logging.error(f'System Exit occurred. Error: {e}')
            sys.exit(1)
        except Exception as e:
            logging.error(f"Failed to update operator-cloud image version in '{file_path}' to '{new_image_tag}'. Error: {e}")
            sys.exit(1)

    def create_branch_for_changes(self, branch_name):
        """Create a new branch from bleeding-edge for making changes."""
        logging.info(f"Creating branch '{branch_name}' from '{self.BLEEDING_EDGE_BRANCH_NAME}'")
        
        # Ensure we're on bleeding-edge and create branch from it
        self.run_command_with_output(f"git checkout {self.BLEEDING_EDGE_BRANCH_NAME}")
        self.run_command_with_output(f"git pull origin {self.BLEEDING_EDGE_BRANCH_NAME}")
        self.run_command_with_output(f"git checkout -B {branch_name}")

    def create_helm_charts_pr(self, commit_message, pr_title, pr_body):
        """Create PR in helm-charts repo and monitor CI status."""
        logging.info(f"Creating helm-charts PR with multi-tenant management cluster updates")
        
        self.run_command_with_output(f'git commit -am "{commit_message}"')
        current_branch = self.run_command_with_output(f"git branch --show-current")
        self.run_command_with_output(f"git push origin -u {current_branch}")
        prUrl = self.run_command_with_output(f"gh pr create --title '{pr_title}' --base '{self.BLEEDING_EDGE_BRANCH_NAME}' --body '{pr_body}' --label 'automerge' --head '{current_branch}'")
        
        ciStateQueryCommand = f'gh pr view {prUrl} --json "statusCheckRollup" --jq \'.statusCheckRollup[] | first(select(.__typename == "StatusContext")) | .state\''
        # There is no guarantee CI will start as soon as the helm-charts PR is opened. We will check every 30 seconds till the CI job starts and exit when it does.
        ciState = self.run_command_with_output(ciStateQueryCommand)
        while (ciState != "PENDING"):
            logging.info(f"CI has not started for {prUrl}. Checking every 30s to see if it has started...")
            time.sleep(30)
            ciState = self.run_command_with_output(ciStateQueryCommand)
        
        logging.info(f"CI for {prUrl} has started. Watching every 30s for helm-charts PR CI check state")  
        rc, ciResult = subprocess.getstatusoutput(f"gh pr checks --fail-fast --watch --interval 30 {prUrl}")
        if rc == 0:
            logging.info(f"Helm Charts PR ({prUrl}) CI check passed with results below:")
            logging.info(ciResult)
        else:
            logging.error(f"Helm Charts PR ({prUrl}) CI check failed with results below:")
            logging.info(ciResult)
            logging.error(f"To resolve, look at the CI job linked to {prUrl} to examine failures and fix them locally.")
            sys.exit(1)

    def run_command_with_output(self, cmd):
        """Run a shell command and return the result."""
        try:
            result = subprocess.check_output(cmd, shell=True, env=self.ENV).decode(sys.stdout.encoding).strip()
            logging.info(f"'{cmd}' executed successfully! Output: {result}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to run command: '{cmd}'. Error: {e}")
            sys.exit(1)

        return result

    def update_multi_tenant_management_cluster(self):
        """Main method to update multi-tenant management cluster charts."""
        try:
            logging.info("Starting multi-tenant management cluster hashrelease update")
            logging.info(f"Hashrelease URL: {self.hashReleaseUrl}")
            logging.info(f"Chart version: {self.chartVersion}")
            logging.info(f"Image tag: {self.imageTag}")

            # Extract hashrelease name for branch naming
            hashrelease_name = self.extract_hashrelease_name()
            branch_name = f"mt-hashrelease-update-{hashrelease_name}"
            
            # Create branch BEFORE making any changes
            self.create_branch_for_changes(branch_name)
            
            # Update chart dependency versions
            logging.info(f"Updating version parameters in multiple files with chart version: {self.chartVersion}")
            
            changes_made = False
            for chart_file, dependency_name in self.charts_to_update:
                if self.update_chart_dependency_version(chart_file, dependency_name, self.chartVersion):
                    changes_made = True
            
            # Update values files with imageTag
            logging.info(f"Updating values files with image tag: {self.imageTag}")
            for values_file in self.values_files_to_update:
                if self.update_values_file_image_version(values_file, self.imageTag):
                    changes_made = True
            
            if not changes_made:
                logging.error("No changes were made to any chart files. Aborting.")
                sys.exit(1)
            
            # Prepare commit message
            commit_message = f"Update multi-tenant management cluster with hashrelease {hashrelease_name} (chart: {self.chartVersion}, image: {self.imageTag})"
            
            # Prepare PR details
            pr_body = f"""This PR updates the multi-tenant management cluster with hashrelease {hashrelease_name}.

**Changes:**
- Updated tigera-operator chart version to `{self.chartVersion}`
- Updated operator-cloud image version to `{self.imageTag}`
- Based on hashrelease: {self.hashReleaseUrl}

**Auto-generated by:** ArgoCI hashrelease workflow"""
            
            pr_title = f"[Hashrelease Automation] Update MT management cluster with hashrelease {hashrelease_name}"
            
            # Create PR and monitor CI
            self.create_helm_charts_pr(commit_message, pr_title, pr_body)
            
            logging.info("Multi-tenant management cluster hashrelease update completed successfully")
            
        except FileNotFoundError:
            logging.error(f"Helm charts repository not found. Please ensure the repository is accessible.")
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            logging.error(f"Command failed with exit code {e.returncode}: {e.cmd}")
            sys.exit(1)
        except SystemExit as e:
            logging.error(f'System Exit occurred. Error: {e}')
            sys.exit(1)
        except Exception as e:
            logging.error(f"Failed to update helm-charts repo to use hashrelease '{self.hashReleaseUrl}'. Error: {e}")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Updates the multi-tenant management cluster charts with hashrelease versions")

    parser.add_argument(
        "--hashReleaseUrl",
        type=str,
        required=True,
        help="The url of the enterprise hashrelease. eg. https://2023-09-12-v3-18-turkey.docs.eng.tigera.net"
    )

    parser.add_argument(
        "--imageTag",
        type=str,
        required=True,
        help="The operator-cloud image tag to update in values files."
    )

    args = parser.parse_args()
    mtClusterUpdater = MultiTenantClusterUpdater(args.hashReleaseUrl, args.imageTag)
    mtClusterUpdater.update_multi_tenant_management_cluster()


if __name__ == "__main__":
    main()