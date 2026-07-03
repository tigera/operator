import pytest
import sys
import management_cluster_updater
from unittest.mock import patch, MagicMock

@pytest.fixture
def setup_test(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLUSTER_ID", "test_cluster_id")

valid_inputs = [
    ("ab34u24h", "2025-02-12-master-unmixed-tesla-d8b3e933", "https://2025-02-12-master-unmixed.docs.eng.tigera.net/", '')
]
@pytest.mark.parametrize("clusterId, imageTag, hashReleaseUrl, expected", valid_inputs)
def test_successful_initialization(clusterId: str, imageTag: str, hashReleaseUrl: str, expected: str, capsys: pytest.CaptureFixture) -> None:
    cluster_updater = management_cluster_updater.ManagementClusterUpdater(clusterId, imageTag, hashReleaseUrl)
    assert cluster_updater.clusterId == clusterId
    assert cluster_updater.imageTag == imageTag
    assert cluster_updater.hashReleaseUrl in hashReleaseUrl
    out, err = capsys.readouterr()
    assert expected in out
    assert '' in err

valid_inputs = [
    ("    ab34u24h    ", "   2025-02-12-master-unmixed-tesla-d8b3e933  ", "https://2025-02-12-master-unmixed.docs.eng.tigera.net/  ", '')
]
@pytest.mark.parametrize("clusterId, imageTag, hashReleaseUrl, expected", valid_inputs)
def test_successful_initialization_with_whitespace(clusterId: str, imageTag: str, hashReleaseUrl: str, expected: str, capsys: pytest.CaptureFixture) -> None:
    cluster_updater = management_cluster_updater.ManagementClusterUpdater(clusterId, imageTag, hashReleaseUrl)
    assert cluster_updater.clusterId == clusterId.strip()
    assert cluster_updater.imageTag == imageTag.strip()
    assert cluster_updater.hashReleaseUrl == hashReleaseUrl.strip().rstrip('/')
    out, err = capsys.readouterr()
    assert expected in out
    assert '' in err

valid_inputs = [
    ("", "2025-02-12-master-unmixed-tesla-d8b3e933", "https://2025-02-12-master-unmixed.docs.eng.tigera.net/", '')
]
@pytest.mark.parametrize("clusterId, imageTag, hashReleaseUrl, expected", valid_inputs)
def test_successful_default_initialization_when_cluster_id_not_defined(clusterId: str, imageTag: str, hashReleaseUrl: str, expected: str, capsys: pytest.CaptureFixture) -> None:
    cluster_updater = management_cluster_updater.ManagementClusterUpdater(clusterId, imageTag, hashReleaseUrl)
    assert cluster_updater.clusterId == "yjefe7y1"
    assert cluster_updater.imageTag == imageTag
    assert cluster_updater.hashReleaseUrl in hashReleaseUrl
    out, err = capsys.readouterr()
    assert expected in out
    assert '' in err

valid_inputs = [
    ("", "2025-02-12-master-unmixed-tesla-d8b3e933", "https://2025-02-12-master-unmixed.docs.eng.tigera.net/", '')
]
@pytest.mark.parametrize("clusterId, imageTag, hashReleaseUrl, expected", valid_inputs)
@pytest.mark.usefixtures("setup_test")
def test_successful_initialization_when_cluster_id_env_var_defined(clusterId: str, imageTag: str, hashReleaseUrl: str, expected: str, capsys: pytest.CaptureFixture) -> None:
    cluster_updater = management_cluster_updater.ManagementClusterUpdater(clusterId, imageTag, hashReleaseUrl)
    assert cluster_updater.clusterId == "test_cluster_id"
    assert cluster_updater.imageTag == imageTag
    assert cluster_updater.hashReleaseUrl in hashReleaseUrl
    out, err = capsys.readouterr()
    assert expected in out
    assert '' in err

valid_inputs = [
    ("https://2025-02-12-master-unmixed.docs.eng.tigera.net/", "v3.21.0-2.0-calient-0.dev-656-gadefb6c5e727"),
    ("https://2025-02-10-v3-20-wharf.docs.eng.tigera.net/", "v3.20.2-calient-0.dev-3-g2f89f6b62cd0"),
    ("https://2025-02-11-v3-19-jeeringly.docs.eng.tigera.net/", "v3.19.5-calient-0.dev-22-gb63384275cb9")
]
@pytest.mark.parametrize("hashReleaseUrl, expected", valid_inputs)
@patch('management_cluster_updater.requests.get')
def test_getting_revision_value_is_successful_from_valid_url(mock_get: MagicMock, hashReleaseUrl: str, expected: str, capsys: pytest.CaptureFixture) -> None:
    # Mock the HTTP response
    mock_response = MagicMock()
    mock_response.content.decode.return_value = f"- title: {expected}\n  version: 1.0.0"
    mock_get.return_value = mock_response
    
    cluster_updater = management_cluster_updater.ManagementClusterUpdater("fake-id", "fake-tag", hashReleaseUrl)
    revision = cluster_updater.get_revision_from_hashrelease_url(hashReleaseUrl)
    assert revision == expected
    out, err = capsys.readouterr()
    assert '' in err

invalid_inputs = [
    ("https://fake-hashrelease.docs.eng.tigera.net/", "Failed to get revision from https://fake-hashrelease.docs.eng.tigera.net")
]
@pytest.mark.parametrize("hashReleaseUrl, expected_msg", invalid_inputs)
@patch('management_cluster_updater.requests.get')
def test_getting_revision_value_is_not_successful_invalid_url(mock_get: MagicMock, hashReleaseUrl: str, expected_msg: str, caplog: pytest.LogCaptureFixture) -> None:
    # Mock the HTTP request to raise an exception
    mock_get.side_effect = Exception("Connection failed")
    
    with pytest.raises(SystemExit) as info:
        cluster_updater = management_cluster_updater.ManagementClusterUpdater("fake-id", "fake-tag", hashReleaseUrl)
        cluster_updater.get_revision_from_hashrelease_url(hashReleaseUrl)
    assert str(info.value) == '1'
    assert expected_msg in caplog.text

invalid_inputs = [
    ("p5z8po1b", "", "some-hashrelease-url", "Image tag not defined, please specify an operator-cloud image tag"),
    ("p5z8po1b", "2023-08-26-v3-18-fifty-tesla-1d5c49ad", "", "Hashrelease URL is not defined, please specify the url")
]
@pytest.mark.parametrize("clusterId, imageTag, hashReleaseUrl, expected_msg", invalid_inputs)
def test_invalid_initialization(clusterId: str, imageTag: str, hashReleaseUrl: str, expected_msg: str) -> None:
    with pytest.raises(AttributeError) as info:
        management_cluster_updater.ManagementClusterUpdater(clusterId, imageTag, hashReleaseUrl)
    assert str(info.value) == expected_msg

invalid_inputs = [
    ("", "2023-08-26-v3-18-fifty-tesla-1d5c49ad", "some-hashrelease-url", "Cluster ID not defined, please specify the cluster ID")
]
@pytest.mark.parametrize("clusterId, imageTag, hashReleaseUrl, expected_msg", invalid_inputs)
def test_invalid_cluster_id_initialization(clusterId: str, imageTag: str, hashReleaseUrl: str, expected_msg: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLUSTER_ID", "")
    with pytest.raises(AttributeError) as info:
        management_cluster_updater.ManagementClusterUpdater(clusterId, imageTag, hashReleaseUrl)
    assert str(info.value) == expected_msg

def test_cli_help_output_is_generated(capsys: pytest.CaptureFixture) -> None:
    sys.argv = ['management_cluster_updater.py', '-h']
    with pytest.raises(SystemExit):
        management_cluster_updater.main()
    out, err = capsys.readouterr()
    assert 'Updates the management cluster to a specified hashrelease via ArgoCD' in out

if __name__ == "__main__":
    pytest.main()
