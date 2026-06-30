import os
import pytest
import sys
import managed_cluster_version_updater
import ruamel.yaml
from unittest.mock import MagicMock
from _pytest.monkeypatch import MonkeyPatch
from _pytest.capture import CaptureFixture

@pytest.fixture
def setup_test(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv('MANAGED_VERSIONS_FILE_PATH', f"{os.getcwd()}/managed-versions-test-data.yaml")

valid_inputs = [
    ("https://2023-09-12-v3-18-turkey.docs.eng.tigera.net", "")
]
@pytest.mark.parametrize("hashReleaseURL, expected", valid_inputs)
@pytest.mark.usefixtures("setup_test")
def test_successful_initialization_flow(hashReleaseURL: str, expected: str, capsys: CaptureFixture) -> None:
    managedClusterUpdater = managed_cluster_version_updater.ManagedClusterVersionUpdater(hashReleaseURL)
    assert str(managedClusterUpdater.hashReleaseURL) == hashReleaseURL
    out, err = capsys.readouterr()
    assert expected in out
    assert '' in err

invalid_inputs = [
    ("",  "Hash Release URL is not defined, please specify the hashrelease URL")
]
@pytest.mark.parametrize("hashReleaseURL, expected", invalid_inputs)
@pytest.mark.usefixtures("setup_test")
def test_invalid_initialization_flow(hashReleaseURL: str, expected: str) -> None:
    with pytest.raises(AttributeError) as info:
        managed_cluster_version_updater.ManagedClusterVersionUpdater(hashReleaseURL)
    assert str(info.value) == expected

def test_invalid_versions_file_path() -> None:
    with pytest.raises(AttributeError) as info:
        managed_cluster_version_updater.ManagedClusterVersionUpdater("my-hashrelease")
    assert str(info.value) == "Managed versions file path is not defined, please specify the path to the managed versions file"

@pytest.mark.usefixtures("setup_test")
def test_helm_charts_versions_yaml_gets_updated() -> None:
    managedClusterUpdater = managed_cluster_version_updater.ManagedClusterVersionUpdater("my-hashrelease")
    managedClusterUpdater.create_helm_charts_pr = MagicMock(return_value=None)
    output = managedClusterUpdater.update_managed_cluster_version_helm_charts()
    assert output is None

    # Check yaml got updated
    yaml = ruamel.yaml.YAML()
    with open(os.environ["MANAGED_VERSIONS_FILE_PATH"], "r") as updated_managed_versions_file:
      updated_managed_versions_yaml = yaml.load(updated_managed_versions_file)
      versions_list = updated_managed_versions_yaml.get("managedClusterVersions", {}).get("versions", [])
      for version_entry in versions_list:
          if "bleeding-edge" in version_entry["version"]:
              assert version_entry["enterpriseDownloadUrl"] == "my-hashrelease"
            
def test_cli_help_output_is_generated(capsys: CaptureFixture) -> None:
    sys.argv = ['managed_cluster_version_updater.py', '-h']
    with pytest.raises(SystemExit):
        managed_cluster_version_updater.main()
    out, err = capsys.readouterr()
    assert 'Creates a PR to the helm-charts repo to update the EE hashrelease URL' in out

if __name__ == "__main__":
    pytest.main()
