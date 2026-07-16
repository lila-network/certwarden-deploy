package certificates

import "github.com/lila-network/certwarden-deploy/internal/configuration"

type FileType int

const (
	CertificateFile FileType = iota
	KeyFile
	CaCertificateFile

	// PrivateCertFile is the certificate and its private key in one file.
	PrivateCertFile

	// PrivateCertChainFile is the certificate, its private key and the CA
	// chain in one file.
	PrivateCertChainFile
)

func (file FileType) String() string {
	switch file {
	case CertificateFile:
		return "certificate"
	case KeyFile:
		return "key"
	case CaCertificateFile:
		return "ca"
	case PrivateCertFile:
		return "privatecert"
	case PrivateCertChainFile:
		return "privatecertchain"
	}

	return "unknown"
}

// RolloutState describes what a rollout did to a single artefact on disk.
//
// The distinction between Created and Modified is what lets a run tell a first
// deployment apart from a renewal, which is what run_on and the run summary
// are built on.
type RolloutState int

const (
	// Unchanged means the file on disk already matched the server content, so
	// nothing was written. A skipped artefact (no path configured) is
	// Unchanged too: nothing happened to it.
	Unchanged RolloutState = iota

	// Created means the file did not exist on disk before this run.
	Created

	// Modified means the file existed and its content differed.
	Modified
)

func (s RolloutState) String() string {
	switch s {
	case Unchanged:
		return "unchanged"
	case Created:
		return "created"
	case Modified:
		return "modified"
	}

	return "unknown"
}

// GenericCertificate is a generic container to enable us to
// handle both certificates and keys with one function
type GenericCertificate struct {
	Name     string
	FilePath string
	Secret   string

	// HTTP tunes the request made for this artefact. The zero value is usable
	// and keeps the behaviour this tool had before the http block existed.
	HTTP configuration.HTTPSettings

	// Type of the certificate
	Type FileType

	// Format is the container requested from the server for the privatecert
	// and privatecertchain endpoints. Empty means the server default, pem.
	Format string

	// Bytes fetched from the server
	serverBytes []byte

	// Bytes fetched from disk
	diskBytes []byte

	// state is what Prepare decided this artefact's rollout would do, kept so
	// Commit can report a first deployment differently from a renewal. It is
	// Unchanged for an artefact that staged nothing.
	state RolloutState

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
	// New holds the names of certificates where at least one artefact did not
	// exist on disk before this run.
	//
	// A certificate is New as soon as any of its artefacts was created, even
	// if the others merely changed: the first deployment is the more
	// interesting fact about that run.
	New []string

	// Changed holds the names of certificates where nothing was created but at
	// least one artefact was written with different content
	Changed []string

	// Unchanged holds the names of certificates that were already up to date
	Unchanged []string

	// Failed holds every artefact that could not be rolled out
	Failed []CertFailure

	// ActionFailed holds every post-rollout action that failed
	ActionFailed []ActionFailure

	// ActionSkipped holds the names of certificates whose action would have
	// run but was suppressed because actions are disabled for this run.
	//
	// A suppressed action is not a failure: it never reaches ExitCode. It is
	// tracked so a run with actions off can say so instead of just looking
	// like a run where nothing needed doing.
	ActionSkipped []string
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
