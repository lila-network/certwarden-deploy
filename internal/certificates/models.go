package certificates

type FileType int

const (
	CertificateFile FileType = iota
	KeyFile
	CaCertificateFile
)

func (file FileType) String() string {
	switch file {
	case CertificateFile:
		return "certificate"
	case KeyFile:
		return "key"
	case CaCertificateFile:
		return "ca"
	}

	return "unknown"
}

// GenericCertificate is a generic container to enable us to
// handle both certificates and keys with one function
type GenericCertificate struct {
	Name     string
	FilePath string
	Secret   string

	// Type of the certificate
	Type FileType

	// Bytes fetched from the server
	serverBytes []byte

	// Bytes fetched from disk
	diskBytes []byte

	// tempPath is the fully written and fsynced file staged by Prepare that has
	// not been renamed into place yet. It is empty whenever nothing is staged:
	// an artefact that was never prepared, one that needed no rollout, one that
	// was already committed and one that was aborted all leave it empty.
	tempPath string
}

// Exit codes returned by a certwarden-deploy run. They form a public contract
// that supervisors (systemd, cron, CI) rely on, so the numbers must be stable.
//
//	0 - every certificate was processed and every triggered action succeeded
//	1 - config/setup error (owned by the CLI layer, not by RunResult)
//	2 - one or more certificates failed to roll out
//	3 - all certificates rolled out, but one or more actions failed
const (
	ExitSuccess            = 0
	ExitCertificateFailure = 2
	ExitActionFailure      = 3
)

// CertFailure records a single certificate artefact that failed to roll out.
//
// Kept deliberately small: name, which artefact broke, and why. That is enough
// to render a summary or to feed a notification without re-deriving context.
type CertFailure struct {
	// Name of the certificate as configured in the config file
	Name string

	// Type of the artefact that failed (certificate, key or CA)
	Type FileType

	// Err is the (wrapped) error that caused the failure
	Err error
}

// ActionFailure records a post-rollout action that exited non-zero.
type ActionFailure struct {
	// Name of the certificate whose action failed
	Name string

	// Err is the error returned by the action
	Err error
}

// RunResult is the outcome of a single HandleCertificates run.
//
// It records what happened per certificate instead of aborting on the first
// problem: a run keeps going after a failure, and the result is only turned
// into an exit code once every certificate has been attempted.
type RunResult struct {
	// New holds the names of certificates that were deployed for the first
	// time.
	//
	// Always empty for now: Rollout only reports a plain "changed" bool, so a
	// first deployment cannot be told apart from an update. #31 will make
	// needsRollout tri-state and populate this field.
	New []string

	// Changed holds the names of certificates where at least one artefact was
	// written to disk
	Changed []string

	// Unchanged holds the names of certificates that were already up to date
	Unchanged []string

	// Failed holds every artefact that could not be rolled out
	Failed []CertFailure

	// ActionFailed holds every post-rollout action that failed
	ActionFailed []ActionFailure
}

// ExitCode maps the result of a run onto the process exit code.
//
// Certificate failures outrank action failures: a certificate that never
// reached the disk is the more severe problem, and an action failure on top of
// it does not make the run any more broken.
func (r *RunResult) ExitCode() int {
	switch {
	case len(r.Failed) > 0:
		return ExitCertificateFailure
	case len(r.ActionFailed) > 0:
		return ExitActionFailure
	default:
		return ExitSuccess
	}
}
