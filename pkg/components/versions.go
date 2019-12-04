package components

// This section contains images used when installing open-source Calico.
const (
	VersionCalicoNode            = "v3.10.0"
	VersionCalicoCNI             = "v3.10.0"
	VersionCalicoTypha           = "v3.10.0"
	VersionCalicoKubeControllers = "v3.10.0"
	VersionFlexVolume            = "v3.10.0"
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	VersionTigeraNode            = "v2.6.0-0.dev-175-g3f547b6"
	VersionTigeraTypha           = "v2.6.0-0.dev-104-g6c51073"
	VersionTigeraKubeControllers = "v2.6.0-0.dev-86-g506e244-dirty"

	// API server images.
	VersionAPIServer   = "v2.7.0-0.dev-16-g64e84f77"
	VersionQueryServer = "v2.6.0-0.dev-12-gca85666"

	// Logging
	VersionFluentd = "v2.6.0-0.dev-33-g382faf2"

	// Compliance images.
	VersionComplianceController  = "v2.7.0-0.dev-22-gf5eb877"
	VersionComplianceReporter    = "v2.7.0-0.dev-22-gf5eb877"
	VersionComplianceServer      = "v2.7.0-0.dev-22-gf5eb877"
	VersionComplianceSnapshotter = "v2.7.0-0.dev-22-gf5eb877"
	VersionComplianceBenchmarker = "v2.7.0-0.dev-22-gf5eb877"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "v2.7.0-0.dev-15-g44db458"
	VersionIntrusionDetectionJobInstaller = "v2.6.0-0.dev-53-g6045051"

	// Manager images.
	VersionManager        = "v2.5.0-347-gb01f72d0"
	VersionManagerProxy   = "v2.7.0-0.dev-14-g0421b7b"
	VersionManagerEsProxy = "v2.6.0-0.dev-96-g38d646f"

	// ECK Elasticsearch images
	VersionECKOperator      = "0.9.0"
	VersionECKElasticsearch = "7.3.2"
	VersionECKKibana        = "7.3.2"
	VersionEsCurator        = "v2.6.0-0.dev-25-gb04da05"

	VersionKibana = "7.3"
)
