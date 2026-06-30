import os
import pytest
import sys
import tempfile
from unittest.mock import MagicMock, patch, mock_open
from _pytest.monkeypatch import MonkeyPatch
from _pytest.capture import CaptureFixture
import mt_management_cluster_updater


class TestMultiTenantClusterUpdater:
    """Test cases for MultiTenantClusterUpdater class."""

    # Test constants - version agnostic
    TEST_IMAGE_TAG = "test-image-v1.0.0"
    TEST_OLD_IMAGE_TAG = "old-version-123"
    TEST_CHART_VERSION_OLD = "v3.17.0"
    TEST_CHART_VERSION_NEW = "v3.18.0"
    TEST_HASHRELEASE_URL = "https://test.docs.eng.tigera.net"
    TEST_HASHRELEASE_URL_2 = "https://2023-09-12-v3-18-turkey.docs.eng.tigera.net"

    # Mock pinned_components.yml response for initialization tests
    @pytest.fixture
    def mock_requests_get(self):
        with patch('requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.raise_for_status.return_value = None
            mock_response.text = """title: v3.18.0-1.0-test-dev-123
release_name: 2023-09-12-v3-18-turkey
components:
  calico: v3.18.0"""
            mock_get.return_value = mock_response
            yield mock_get

    # Test initialization scenarios
    valid_initialization_inputs = [
        ("https://2023-09-12-v3-18-turkey.docs.eng.tigera.net", TEST_IMAGE_TAG, ""),
        ("https://2024-01-15-v3-19-eagle.docs.eng.tigera.net/", "master-abc123", ""),
    ]

    @pytest.mark.parametrize("hashReleaseUrl, imageTag, expected", valid_initialization_inputs)
    def test_successful_initialization(self, hashReleaseUrl: str, imageTag: str, expected: str, capsys: CaptureFixture, mock_requests_get) -> None:
        """Test successful initialization with valid parameters."""
        updater = mt_management_cluster_updater.MultiTenantClusterUpdater(hashReleaseUrl, imageTag)
        assert updater.hashReleaseUrl == hashReleaseUrl.strip().rstrip('/')
        assert updater.imageTag == imageTag.strip()
        assert updater.chartVersion == "v3.18.0-1.0-test-dev-123"  # From mock response
        out, err = capsys.readouterr()
        assert expected in out

    whitespace_inputs = [
        ("  https://2023-09-12-v3-18-turkey.docs.eng.tigera.net/  ", f"  {TEST_IMAGE_TAG}  ", ""),
    ]

    @pytest.mark.parametrize("hashReleaseUrl, imageTag, expected", whitespace_inputs)
    def test_successful_initialization_with_whitespace(self, hashReleaseUrl: str, imageTag: str, expected: str, capsys: CaptureFixture, mock_requests_get) -> None:
        """Test successful initialization with whitespace in parameters."""
        updater = mt_management_cluster_updater.MultiTenantClusterUpdater(hashReleaseUrl, imageTag)
        assert updater.hashReleaseUrl == hashReleaseUrl.strip().rstrip('/')
        assert updater.imageTag == imageTag.strip()
        assert updater.chartVersion == "v3.18.0-1.0-test-dev-123"  # From mock response
        out, err = capsys.readouterr()
        assert expected in out

    # Test invalid initialization scenarios
    invalid_hashrelease_inputs = [
        ("", TEST_IMAGE_TAG, "Hashrelease URL is not defined, please specify the url"),
        (None, TEST_IMAGE_TAG, "Hashrelease URL is not defined, please specify the url"),
    ]

    @pytest.mark.parametrize("hashReleaseUrl, imageTag, expected", invalid_hashrelease_inputs)
    def test_invalid_hashrelease_initialization(self, hashReleaseUrl: str, imageTag: str, expected: str) -> None:
        """Test initialization failure with invalid hashReleaseUrl."""
        with pytest.raises(AttributeError) as info:
            mt_management_cluster_updater.MultiTenantClusterUpdater(hashReleaseUrl, imageTag)
        assert str(info.value) == expected

    invalid_imagetag_inputs = [
        ("https://2023-09-12-v3-18-turkey.docs.eng.tigera.net", "", "Image tag is empty, please specify a valid operator-cloud image tag"),
        ("https://2023-09-12-v3-18-turkey.docs.eng.tigera.net", None, "Image tag is empty, please specify a valid operator-cloud image tag"),
        ("https://2023-09-12-v3-18-turkey.docs.eng.tigera.net", "   ", "Image tag is empty, please specify a valid operator-cloud image tag"),
    ]

    @pytest.mark.parametrize("hashReleaseUrl, imageTag, expected", invalid_imagetag_inputs)
    def test_invalid_imagetag_initialization(self, hashReleaseUrl: str, imageTag: str, expected: str) -> None:
        """Test initialization failure with invalid imageTag."""
        with pytest.raises(AttributeError) as info:
            mt_management_cluster_updater.MultiTenantClusterUpdater(hashReleaseUrl, imageTag)
        assert str(info.value) == expected

    # Test chart version fetching from hashrelease
    def test_get_chart_version_from_hashrelease_success(self, mock_requests_get) -> None:
        """Test successful chart version fetching from pinned_components.yml."""
        updater = mt_management_cluster_updater.MultiTenantClusterUpdater(
            self.TEST_HASHRELEASE_URL_2, self.TEST_IMAGE_TAG
        )
        chart_version = updater.get_chart_version_from_hashrelease()
        assert chart_version == "v3.18.0-1.0-test-dev-123"
        mock_requests_get.assert_called_with(f"{self.TEST_HASHRELEASE_URL_2}/pinned_components.yml")

    def test_get_chart_version_from_hashrelease_failure(self) -> None:
        """Test chart version fetching failure with invalid URL."""
        with patch('requests.get') as mock_get:
            mock_get.side_effect = Exception("Network error")
            with pytest.raises(Exception):
                updater = mt_management_cluster_updater.MultiTenantClusterUpdater(
                    "https://invalid-url", self.TEST_IMAGE_TAG
                )

    def test_get_chart_version_missing_title_field(self) -> None:
        """Test chart version fetching when title field is missing."""
        with patch('requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.raise_for_status.return_value = None
            mock_response.text = """release_name: 2023-09-12-v3-18-turkey
components:
  calico: v3.18.0"""
            mock_get.return_value = mock_response
            with pytest.raises(ValueError, match="'title' field not found in pinned_components.yml"):
                updater = mt_management_cluster_updater.MultiTenantClusterUpdater(
                    "https://test-url", self.TEST_IMAGE_TAG
                )

    # Test hashrelease name extraction
    hashrelease_name_inputs = [
        ("https://2023-09-12-v3-18-turkey.docs.eng.tigera.net", "2023-09-12-v3-18-turkey"),
        ("https://2024-01-15-v3-19-eagle.docs.eng.tigera.net/", "2024-01-15-v3-19-eagle"),
        ("2023-09-12-v3-18-turkey.docs.eng.tigera.net", "2023-09-12-v3-18-turkey"),
    ]

    @pytest.mark.parametrize("hashReleaseUrl, expected_name", hashrelease_name_inputs)
    def test_extract_hashrelease_name(self, hashReleaseUrl: str, expected_name: str, mock_requests_get) -> None:
        """Test hashrelease name extraction from URL."""
        updater = mt_management_cluster_updater.MultiTenantClusterUpdater(hashReleaseUrl, self.TEST_IMAGE_TAG)
        result = updater.extract_hashrelease_name()
        assert result == expected_name

    # Test file update methods
    def test_update_chart_dependency_version_success_non_tigera_operator_chart(self, mock_requests_get) -> None:
        """Test successful chart dependency version update for non-tigera-operator charts (expects 1 update)."""
        updater = mt_management_cluster_updater.MultiTenantClusterUpdater(
            self.TEST_HASHRELEASE_URL, self.TEST_IMAGE_TAG
        )
        
        # Create a temporary file with chart content (1 dependency for non-tigera-operator charts)
        chart_content = """apiVersion: v2
name: test-chart
version: 1.0.0
dependencies:
- name: tigera-operator
  version: {self.TEST_CHART_VERSION_OLD}
  repository: file://../tigera-operator
"""
        expected_content = f"""apiVersion: v2
name: test-chart
version: 1.0.0
dependencies:
- name: tigera-operator
  version: {self.TEST_CHART_VERSION_NEW}
  repository: file://../tigera-operator
"""
        
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.yaml') as temp_file:
            temp_file.write(chart_content)
            temp_file.flush()
            
            try:
                result = updater.update_chart_dependency_version(temp_file.name, "tigera-operator", self.TEST_CHART_VERSION_NEW)
                assert result is True
                
                # Verify the file was updated correctly
                with open(temp_file.name, 'r') as f:
                    updated_content = f.read()
                assert updated_content == expected_content
            finally:
                os.unlink(temp_file.name)

    def test_update_chart_dependency_version_success_tigera_operator_chart(self, mock_requests_get) -> None:
        """Test successful chart dependency version update for tigera-operator chart (expects 2 updates)."""
        updater = mt_management_cluster_updater.MultiTenantClusterUpdater(
            self.TEST_HASHRELEASE_URL, self.TEST_IMAGE_TAG
        )
        
        # Create a temporary file that mimics the tigera-operator chart path (needs 2 tigera-operator dependencies)
        chart_content = f"""apiVersion: v2
name: tigera-operator
version: 1.0.0
dependencies:
- name: tigera-operator
  version: {self.TEST_CHART_VERSION_OLD}
  repository: file://../tigera-operator
- name: tigera-operator
  version: {self.TEST_CHART_VERSION_OLD}
  repository: file://../tigera-operator-alt
"""
        expected_content = f"""apiVersion: v2
name: tigera-operator
version: 1.0.0
dependencies:
- name: tigera-operator
  version: {self.TEST_CHART_VERSION_NEW}
  repository: file://../tigera-operator
- name: tigera-operator
  version: {self.TEST_CHART_VERSION_NEW}
  repository: file://../tigera-operator-alt
"""
        
        # Create a temporary directory structure to simulate tigera-operator chart path
        with tempfile.TemporaryDirectory() as temp_dir:
            chart_dir = os.path.join(temp_dir, 'charts', 'tigera-operator')
            os.makedirs(chart_dir, exist_ok=True)
            temp_file_path = os.path.join(chart_dir, 'Chart.yaml')
            
            with open(temp_file_path, 'w') as f:
                f.write(chart_content)
            
            result = updater.update_chart_dependency_version(temp_file_path, "tigera-operator", self.TEST_CHART_VERSION_NEW)
            assert result is True
            
            # Verify the file was updated correctly
            with open(temp_file_path, 'r') as f:
                updated_content = f.read()
            assert updated_content == expected_content

    def test_update_chart_dependency_version_file_not_found(self, mock_requests_get) -> None:
        """Test chart dependency version update with non-existent file."""
        updater = mt_management_cluster_updater.MultiTenantClusterUpdater(
            self.TEST_HASHRELEASE_URL, self.TEST_IMAGE_TAG
        )
        
        result = updater.update_chart_dependency_version("/non/existent/file.yaml", "tigera-operator", self.TEST_CHART_VERSION_NEW)
        assert result is False

    def test_update_chart_dependency_version_dependency_not_found(self, mock_requests_get) -> None:
        """Test chart dependency version update when dependency is not found."""
        updater = mt_management_cluster_updater.MultiTenantClusterUpdater(
            self.TEST_HASHRELEASE_URL, self.TEST_IMAGE_TAG
        )
        
        chart_content = """apiVersion: v2
name: test-chart
version: 1.0.0
dependencies:
- name: other-dependency
  version: v1.0.0
"""
        
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.yaml') as temp_file:
            temp_file.write(chart_content)
            temp_file.flush()
            
            try:
                result = updater.update_chart_dependency_version(temp_file.name, "tigera-operator", self.TEST_CHART_VERSION_NEW)
                assert result is False
            finally:
                os.unlink(temp_file.name)

    def test_update_chart_dependency_version_tigera_operator_chart_insufficient_dependencies(self, mock_requests_get) -> None:
        """Test tigera-operator chart when only 1 tigera-operator dependency is found (should return False as exactly 2 are required)."""
        updater = mt_management_cluster_updater.MultiTenantClusterUpdater(
            self.TEST_HASHRELEASE_URL, self.TEST_IMAGE_TAG
        )
        
        chart_content = f"""apiVersion: v2
name: tigera-operator
version: 1.0.0
dependencies:
- name: tigera-operator
  version: {self.TEST_CHART_VERSION_OLD}
  repository: file://../tigera-operator
- name: other-dependency
  version: v1.0.0
"""
        
        # Create a temporary directory structure to simulate tigera-operator chart path
        with tempfile.TemporaryDirectory() as temp_dir:
            chart_dir = os.path.join(temp_dir, 'charts', 'tigera-operator')
            os.makedirs(chart_dir, exist_ok=True)
            temp_file_path = os.path.join(chart_dir, 'Chart.yaml')
            
            with open(temp_file_path, 'w') as f:
                f.write(chart_content)
            
            result = updater.update_chart_dependency_version(temp_file_path, "tigera-operator", self.TEST_CHART_VERSION_NEW)
            assert result is False  # Should return False because only 1 update was made, but exactly 2 are required for tigera-operator chart

    def test_update_values_file_image_version_success(self, mock_requests_get) -> None:
        """Test successful values file image version update."""
        updater = mt_management_cluster_updater.MultiTenantClusterUpdater(
            self.TEST_HASHRELEASE_URL, self.TEST_IMAGE_TAG
        )
        
        values_content = f"""tigeraMultiTenantOperator:
  enabled: true
  tigeraOperator:
    image: tigera-cc-dev/operator-cloud
    version: {self.TEST_OLD_IMAGE_TAG}
    registry: gcr.io
"""
        expected_content = f"""tigeraMultiTenantOperator:
  enabled: true
  tigeraOperator:
    image: tigera-cc-dev/operator-cloud
    version: {self.TEST_IMAGE_TAG}
    registry: gcr.io
"""
        
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.yaml') as temp_file:
            temp_file.write(values_content)
            temp_file.flush()
            
            try:
                result = updater.update_values_file_image_version(temp_file.name, self.TEST_IMAGE_TAG)
                assert result is True
                
                # Verify the file was updated correctly
                with open(temp_file.name, 'r') as f:
                    updated_content = f.read()
                assert updated_content == expected_content
            finally:
                os.unlink(temp_file.name)

    def test_update_values_file_image_version_file_not_found(self, mock_requests_get) -> None:
        """Test values file image version update with non-existent file."""
        updater = mt_management_cluster_updater.MultiTenantClusterUpdater(
            self.TEST_HASHRELEASE_URL, self.TEST_IMAGE_TAG
        )
        
        result = updater.update_values_file_image_version("/non/existent/file.yaml", self.TEST_IMAGE_TAG)
        assert result is False

    def test_update_values_file_image_version_pattern_not_found(self, mock_requests_get) -> None:
        """Test values file image version update when pattern is not found."""
        updater = mt_management_cluster_updater.MultiTenantClusterUpdater(
            self.TEST_HASHRELEASE_URL, self.TEST_IMAGE_TAG
        )
        
        values_content = """tigeraMultiTenantOperator:
  enabled: true
  tigeraOperator:
    image: some-other-image
    version: v1.0.0
"""
        
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.yaml') as temp_file:
            temp_file.write(values_content)
            temp_file.flush()
            
            try:
                result = updater.update_values_file_image_version(temp_file.name, self.TEST_IMAGE_TAG)
                assert result is False
            finally:
                os.unlink(temp_file.name)

    # Test main workflow
    @patch('mt_management_cluster_updater.MultiTenantClusterUpdater.run_command_with_output')
    @patch('mt_management_cluster_updater.MultiTenantClusterUpdater.update_chart_dependency_version')
    @patch('mt_management_cluster_updater.MultiTenantClusterUpdater.update_values_file_image_version')
    @patch('mt_management_cluster_updater.MultiTenantClusterUpdater.create_helm_charts_pr')
    def test_update_multi_tenant_management_cluster_success(
        self, mock_create_pr, mock_update_values, mock_update_chart, mock_run_command, mock_requests_get
    ) -> None:
        """Test successful multi-tenant management cluster update workflow."""
        # Setup mocks
        mock_update_chart.return_value = True
        mock_update_values.return_value = True
        mock_create_pr.return_value = None
        
        updater = mt_management_cluster_updater.MultiTenantClusterUpdater(
            self.TEST_HASHRELEASE_URL_2, self.TEST_IMAGE_TAG
        )
        
        # Execute the method
        updater.update_multi_tenant_management_cluster()
        
        # Verify calls were made
        assert mock_update_chart.call_count == 3  # Should be called for each chart file
        assert mock_update_values.call_count == 1  # Should be called for values file
        mock_create_pr.assert_called_once()

    @patch('mt_management_cluster_updater.MultiTenantClusterUpdater.update_chart_dependency_version')
    @patch('mt_management_cluster_updater.MultiTenantClusterUpdater.update_values_file_image_version')
    def test_update_multi_tenant_management_cluster_no_changes(
        self, mock_update_values, mock_update_chart, mock_requests_get
    ) -> None:
        """Test workflow when no changes are made to files."""
        # Setup mocks to return False (no changes)
        mock_update_chart.return_value = False
        mock_update_values.return_value = False
        
        updater = mt_management_cluster_updater.MultiTenantClusterUpdater(
            self.TEST_HASHRELEASE_URL_2, self.TEST_IMAGE_TAG
        )
        
        # Execute and expect SystemExit
        with pytest.raises(SystemExit) as exc_info:
            updater.update_multi_tenant_management_cluster()
        
        assert exc_info.value.code == 1

    # Test CLI help output
    def test_cli_help_output_is_generated(self, capsys: CaptureFixture) -> None:
        """Test that CLI help output is generated correctly."""
        sys.argv = ['mt_management_cluster_updater.py', '-h']
        with pytest.raises(SystemExit):
            mt_management_cluster_updater.main()
        out, err = capsys.readouterr()
        assert 'Updates the multi-tenant management cluster charts with hashrelease versions' in out
        assert '--hashReleaseUrl' in out
        assert '--imageTag' in out

    # Test CLI argument parsing
    @patch('mt_management_cluster_updater.MultiTenantClusterUpdater')
    def test_main_function_calls_updater(self, mock_updater_class) -> None:
        """Test that main function properly parses arguments and calls updater."""
        # Mock the updater instance
        mock_updater_instance = MagicMock()
        mock_updater_class.return_value = mock_updater_instance
        
        # Mock sys.argv
        test_args = [
            'mt_management_cluster_updater.py',
            '--hashReleaseUrl', self.TEST_HASHRELEASE_URL,
            '--imageTag', self.TEST_IMAGE_TAG
        ]
        
        with patch.object(sys, 'argv', test_args):
            mt_management_cluster_updater.main()
        
        # Verify the updater was created with correct arguments
        mock_updater_class.assert_called_once_with(
            self.TEST_HASHRELEASE_URL,
            self.TEST_IMAGE_TAG
        )
        # Verify the update method was called
        mock_updater_instance.update_multi_tenant_management_cluster.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__])