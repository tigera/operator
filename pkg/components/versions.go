package components

// This section contains images used when installing open-source Calico.
const (
	VersionCalicoNode            = "v3.10.0"
	VersionCalicoCNI             = "v3.10.0"
	VersionCalicoTypha           = "v3.10.0"
	VersionCalicoKubeControllers = "v3.10.0"
	VersionFlexVolume            = "v3.10.0"
	VersionCPHAutoscaler         = "1.7.1"
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	VersionTigeraNode            = "v2.6.0-0.dev-175-g3f547b6"
	VersionTigeraTypha           = "v2.6.0-0.dev-104-g6c51073"
	VersionTigeraKubeControllers = "v2.6.0-0.dev-86-g506e244-dirty"

	// API server images.
	VersionAPIServer   = "v2.5.0-mcm0.1-49-g909a7f60"
	VersionQueryServer = "v2.6.0-0.dev-12-gca85666"

	// Logging
	VersionFluentd = "v2.6.0-0.dev-33-g382faf2"

	// Compliance images.
	VersionComplianceController  = "v2.6.0-0.dev-42-g5bb7357"
	VersionComplianceReporter    = "v2.6.0-0.dev-42-g5bb7357"
	VersionComplianceServer      = "v2.6.0-0.dev-42-g5bb7357"
	VersionComplianceSnapshotter = "v2.6.0-0.dev-42-g5bb7357"
	VersionComplianceBenchmarker = "v2.6.0-0.dev-42-g5bb7357"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "v2.6.0-0.dev-53-g6045051"
	VersionIntrusionDetectionJobInstaller = "v2.6.0-0.dev-53-g6045051"

	// Manager images.
	VersionManager        = "v2.5.0-347-gb01f72d0"
	VersionManagerProxy   = "v2.5.0-mcm0.1-27-g9d85a20"
	VersionManagerEsProxy = "v2.6.0-0.dev-96-g38d646f"

	// ECK Elasticsearch images
	VersionECKOperator      = "0.9.0"
	VersionECKElasticsearch = "7.3.2"
	VersionECKKibana        = "7.3.2"
	VersionEsCurator        = "v2.6.0-0.dev-25-gb04da05"

	VersionKibana = "7.3"
)
