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
	VersionTigeraNode            = "v2.7.0-0.dev-182-g50b30eb"
	VersionTigeraTypha           = "v2.7.0-0.dev-70-g781aa81"
	VersionTigeraKubeControllers = "v2.7.0-0.dev-69-g1af2df3"

	// API server images.
	VersionAPIServer   = "v2.7.0-0.dev-30-g440bdf40"
	VersionQueryServer = "v2.7.0-0.dev-23-g94e9908"

	// Logging
	VersionFluentd = "v2.7.0-0.dev-4-gb1486b3"

	// Compliance images.
	VersionComplianceController  = "v2.7.0-0.dev-30-ge695e07"
	VersionComplianceReporter    = "v2.7.0-0.dev-30-ge695e07"
	VersionComplianceServer      = "v2.7.0-0.dev-30-ge695e07"
	VersionComplianceSnapshotter = "v2.7.0-0.dev-30-ge695e07"
	VersionComplianceBenchmarker = "v2.7.0-0.dev-30-ge695e07"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "v2.7.0-0.dev-26-g979dece"
	VersionIntrusionDetectionJobInstaller = "v2.7.0-0.dev-26-g979dece"

	// Manager images.
	VersionManager        = "v2.7.0-0.dev-174-g35f293c0"
	VersionManagerProxy   = "v2.7.0-0.dev-32-gdfdbc7d"
	VersionManagerEsProxy = "v2.7.0-0.dev-31-g610afc1"

	// ECK Elasticsearch images
	VersionECKOperator      = "0.9.0"
	VersionECKElasticsearch = "7.3.2"
	VersionECKKibana        = "7.3.2"
	VersionEsCurator        = "v2.6.0-0.dev-25-gb04da05"

	VersionKibana = "7.3"

	// Multicluster tunnel image.
	VersionGuardian = "v2.7.0-0.dev-32-gdfdbc7d"
)
