package components

// This section contains images used when installing open-source Calico.
const (
	VersionCalicoNode            = "v3.11.1-with-auto-backend"
	VersionCalicoCNI             = "v3.11.1"
	VersionCalicoTypha           = "v3.11.1"
	VersionCalicoKubeControllers = "v3.11.1"
	VersionFlexVolume            = "v3.11.1"
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	VersionTigeraNode            = "v2.7.0-0.dev-188-gc5255d3"
	VersionTigeraTypha           = "v2.7.0-0.dev-74-g67bc0b1"
	VersionTigeraKubeControllers = "v2.7.0-0.dev-94-g1d26407"

	// API server images.
	VersionAPIServer   = "v2.7.0-0.dev-32-gb094281f"
	VersionQueryServer = "v2.7.0-0.dev-26-g232a725"

	// Logging
	VersionFluentd = "v2.7.0-0.dev-4-gb1486b3"

	// Compliance images.
	VersionComplianceController  = "v2.7.0-0.dev-38-g23b93c3"
	VersionComplianceReporter    = "v2.7.0-0.dev-38-g23b93c3"
	VersionComplianceServer      = "v2.7.0-0.dev-38-g23b93c3"
	VersionComplianceSnapshotter = "v2.7.0-0.dev-38-g23b93c3"
	VersionComplianceBenchmarker = "v2.7.0-0.dev-38-g23b93c3"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "v2.7.0-0.dev-27-gd7ce71b"
	VersionIntrusionDetectionJobInstaller = "v2.7.0-0.dev-27-gd7ce71b"

	// Manager images.
	VersionManager        = "v2.7.0-0.dev-234-g952d0a82"
	VersionManagerProxy   = "v2.7.0-0.dev-32-gdfdbc7d"
	VersionManagerEsProxy = "v2.7.0-0.dev-37-gf22e27b"

	// ECK Elasticsearch images
	VersionECKOperator      = "0.9.0"
	VersionECKElasticsearch = "7.3.2"
	VersionECKKibana        = "7.3.2"
	VersionEsCurator        = "v2.6.0-0.dev-25-gb04da05"

	VersionKibana = "7.3"

	// Multicluster tunnel image.
	VersionGuardian = "v2.7.0-0.dev-32-gdfdbc7d"
)
