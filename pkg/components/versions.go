package components

// This section contains images used when installing open-source Calico.
const (
	VersionCalicoNode            = "v3.8.1"
	VersionCalicoCNI             = "v3.8.1"
	VersionCalicoTypha           = "v3.8.1"
	VersionCalicoKubeControllers = "v3.8.1"
	VersionFlexVolume            = "v3.8.1"
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	VersionTigeraNode            = "v2.5.0"
	VersionTigeraTypha           = "v2.4.2"
	VersionTigeraKubeControllers = "v2.4.2"

	// API server images.
	VersionAPIServer   = "v2.5.0"
	VersionQueryServer = "v2.4.0"

	// Compliance images.
	VersionComplianceController  = "v2.4.2"
	VersionComplianceReporter    = "v2.4.2"
	VersionComplianceServer      = "v2.4.2"
	VersionComplianceSnapshotter = "v2.4.2"
	VersionComplianceBenchmarker = "v2.5.0"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "v2.4.2"
	VersionIntrusionDetectionJobInstaller = "v2.4.2"

	// Console images.
	VersionConsoleManager = "sha256:89457981eb9513433d95d665f42c38e6b85d2a76ce5382fc96e12bb9fc69f15b"
	VersionConsoleProxy   = "sha256:e6b4ff92b62661a295eac22ecbbfca593f053c4727c76731f9af59e16b6dc6cb"
	VersionConsoleEsProxy = "v2.4.0"
)
