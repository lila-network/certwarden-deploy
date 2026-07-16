package certificates

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/lila-network/certwarden-deploy/internal/configuration"
	"github.com/lila-network/certwarden-deploy/internal/constants"
)

// HandleCertificates rolls out every configured certificate and reports what
// happened in a RunResult, which the caller turns into an exit code.
//
// A failing certificate never aborts the run: one broken certificate must not
// keep the remaining ones from being deployed. Failures are recorded and the
// loop moves on.
func HandleCertificates(logger *slog.Logger, config *configuration.ConfigFileData) RunResult {
	result := RunResult{}

	httpSettings, settingsErr := config.HTTPSettings()
	if settingsErr.HasMessages() {
		// IsValid rejects a broken http block long before this runs, so getting
		// here means a caller skipped validation. Report it and carry on with
		// the defaults rather than failing every certificate over it.
		settingsErr.Print(logger)
		httpSettings = configuration.DefaultHTTPSettings()
	}

	for _, cert := range config.Certificates {
		state, failure := rolloutCertificate(logger, config, cert, httpSettings)
		if failure != nil {
			result.Failed = append(result.Failed, *failure)
			continue
		}

		// Everything this certificate needed is on disk, so classify it.
		// rolloutCertificate already folded the artefacts into one state.
		switch state {
		case Created:
			result.New = append(result.New, cert.Name)
		case Modified:
			result.Changed = append(result.Changed, cert.Name)
		default:
			result.Unchanged = append(result.Unchanged, cert.Name)
		}

		// run_on is evaluated on the aggregate state of the whole certificate
		// and only once phase 2 has published every artefact, so an action never
		// observes a half-deployed certificate (#28).
		//
		// --force runs the action no matter what run_on says, including
		// run_on: new. That is what --force has always meant here: it forces
		// both the write and the action.
		if actionTriggered(cert.EffectiveRunOn(), state) || configuration.Force {
			if cert.Action.IsEmpty() {
				// An action key that is present but blank is almost certainly a
				// mistake, so say so -- but only warn. Failing the run would
				// punish every certificate in the config for one empty line.
				if cert.Action.IsSet() {
					logger.Warn(
						"Action is configured but empty, nothing will run",
						"name", cert.Name,
					)
				}
				continue
			}

			if !config.ActionsEnabled() {
				// Checked before --dry-run: actions being off is a property of
				// the whole run, and the summary should say so whether or not
				// the run was a simulation. The command is logged so it is
				// obvious what did not happen.
				logger.Info(
					"Actions are disabled, skipping post-rollout action",
					"name", cert.Name, "command", cert.Action.String(),
				)
				result.ActionSkipped = append(result.ActionSkipped, cert.Name)
				continue
			}

			if configuration.DryRun {
				// Actions never run during --dry-run, so they can never fail
				// here and exit code 3 is unreachable in a dry run. A fetch
				// failure above is different: that request really was made and
				// really did fail, so it is recorded and still yields exit 2.
				logger.Info("DRY-RUN: skipping post-rollout action", "name", cert.Name, "command", cert.Action.String())
				continue
			}

			if configuration.Force {
				logger.Info("Forcing file system change due to --force", "name", cert.Name)
			}

			err := handleCertificateAction(logger, cert.Action)
			if err != nil {
				logger.Error("Failed to execute post-rollout action", "name", cert.Name, "error", err)
				result.ActionFailed = append(result.ActionFailed, ActionFailure{Name: cert.Name, Err: err})
			}
		}
	}

	return result
}

// aggregateState folds the states of one certificate's artefacts into the
// state of the certificate as a whole.
//
// New wins over changed: if any artefact was created the certificate is new,
// otherwise if any artefact was modified it changed, otherwise nothing
// happened to it.
func aggregateState(states ...RolloutState) RolloutState {
	result := Unchanged

	for _, state := range states {
		switch state {
		case Created:
			return Created
		case Modified:
			result = Modified
		}
	}

	return result
}

// actionTriggered reports whether a run_on policy fires for a certificate that
// ended up in the given state.
func actionTriggered(policy configuration.RunOnPolicy, state RolloutState) bool {
	switch policy {
	case configuration.RunOnAll:
		return true
	case configuration.RunOnNew:
		return state == Created
	case configuration.RunOnChanged:
		return state == Modified
	default:
		// DefaultRunOn, and the only policy that existed before run_on did
		return state != Unchanged
	}
}

// artefactsOf splits a configured certificate into the individual files it is
// made of. They are deployed as one unit: a certificate is only usable next to
// the key it was issued for.
func artefactsOf(cert configuration.CertificateData, httpSettings configuration.HTTPSettings) []*GenericCertificate {
	return []*GenericCertificate{
		{
			Name:     cert.Name,
			FilePath: cert.CertificatePath,
			Secret:   cert.CertificateSecret,
			HTTP:     httpSettings,
			Type:     CertificateFile,
		},
		{
			Name:     cert.Name,
			FilePath: cert.KeyPath,
			Secret:   cert.KeySecret,
			HTTP:     httpSettings,
			Type:     KeyFile,
		},
		{
			Name:     cert.Name,
			FilePath: cert.CaPath,
			Secret:   cert.CertificateSecret,
			HTTP:     httpSettings,
			Type:     CaCertificateFile,
		},
		{
			Name:     cert.Name,
			FilePath: cert.PrivateCertPath,
			Secret:   combinedSecret(cert),
			HTTP:     httpSettings,
			Type:     PrivateCertFile,
			Format:   cert.PrivateCertFormat,
		},
		{
			Name:     cert.Name,
			FilePath: cert.PrivateCertChainPath,
			Secret:   combinedSecret(cert),
			HTTP:     httpSettings,
			Type:     PrivateCertChainFile,
			Format:   cert.PrivateCertChainFormat,
		},
	}
}

// rolloutCertificate deploys all artefacts of a single certificate as one unit,
// in two phases (#28).
//
// Rolling the artefacts out one by one used to leave a new certificate next to
// the old, non-matching key whenever the key fetch failed after the certificate
// had already been renamed into place. Nothing broke at that moment, because
// nothing reloaded, but the next unrelated restart of the TLS server picked up
// the mismatched pair and failed hours or days after the run that caused it.
//
// So: phase 1 fetches every artefact and stages it as a temporary file next to
// its target, and phase 2 only renames anything once every artefact of this
// certificate made it through phase 1. If any of them fails, phase 2 never
// starts and every staged file is discarded, leaving the certificate exactly as
// it was.
//
// The renames in phase 2 are not atomic as a group: POSIX cannot rename several
// files in one step, so this is not a transaction. What it does is shrink the
// window in which the pair can be inconsistent from seconds of network I/O to
// the microseconds between two renames, and remove the failure mode above
// entirely: by phase 2 all data has been fetched, written and fsynced, so a
// rename can realistically only still fail if the filesystem itself is broken.
//
// Returns the aggregate state of the certificate and a failure to record, if
// any. The state is folded across every artefact, so a certificate whose key
// is new but whose CA merely changed is reported as new (#31).
func rolloutCertificate(
	logger *slog.Logger,
	config *configuration.ConfigFileData,
	cert configuration.CertificateData,
	httpSettings configuration.HTTPSettings,
) (RolloutState, *CertFailure) {
	artefacts := artefactsOf(cert, httpSettings)

	// Phase 2' (abort): discard whatever is still staged when this returns.
	// Abort is a no-op for an artefact that staged nothing and for one that was
	// committed, so on the happy path this does nothing.
	defer func() {
		for _, artefact := range artefacts {
			artefact.Abort(logger)
		}
	}()

	// Phase 1 (prepare): fetch and stage every artefact. Nothing that a TLS
	// server could pick up changes here.
	state := Unchanged
	for _, artefact := range artefacts {
		artefactState, err := artefact.Prepare(logger, config.BaseURL, config.DisableCertificateValidation)
		if err != nil {
			logger.Error(
				"Failed to roll out certificate", "path", artefact.FilePath,
				"name", cert.Name, "file-type", artefact.Type, "error", err,
			)
			return Unchanged, &CertFailure{Name: cert.Name, Type: artefact.Type, Err: err}
		}

		state = aggregateState(state, artefactState)
	}

	// Phase 2 (commit): every artefact is fetched and on disk, publish them.
	for _, artefact := range artefacts {
		if err := artefact.Commit(logger); err != nil {
			logger.Error(
				"Failed to commit certificate", "path", artefact.FilePath,
				"name", cert.Name, "file-type", artefact.Type, "error", err,
			)
			return Unchanged, &CertFailure{Name: cert.Name, Type: artefact.Type, Err: err}
		}
	}

	return state, nil
}

// Prepare is phase 1 of a rollout: it fetches the artefact from the server,
// compares it to what is on disk and, if it differs (or --force is set), stages
// the new content as a fully written and fsynced temporary file next to the
// target. It deliberately stops short of the rename, so a caller can still walk
// away from the whole certificate without having touched it.
//
// The staged file is handed over to Commit or Abort through c.tempPath, which
// is set as soon as the temporary file exists. Every error path out of Prepare
// therefore leaves the file recorded and removable, never orphaned.
// combinedSecret builds the API key that the privatecert and privatecertchain
// endpoints expect.
//
// Those two downloads return the certificate and the private key in one
// response, so CertWarden authenticates them with both secrets at once: the
// certificate secret and the key secret joined by a dot.
func combinedSecret(cert configuration.CertificateData) string {
	return cert.CertificateSecret + "." + cert.KeySecret
}

// Returns error on error, otherwise the state the artefact ended up in:
// Created or Modified if it was staged for deployment, Unchanged if it is
// already up to date.
func (c *GenericCertificate) Prepare(logger *slog.Logger, baseUrl string, skipInsecure bool) (RolloutState, error) {
	// An artefact nobody configured is not deployed at all, not even staged.
	if c.FilePath == "" {
		logger.Info("File path is empty, skipping...", "file-type", c.Type)
		return Unchanged, nil
	}

	err := c.fetchFromServer(
		logger,
		baseUrl,
		skipInsecure,
	)
	if err != nil {
		return Unchanged, fmt.Errorf("failed to get certificate from server: %w", err)
	}

	state, err := c.needsRollout(logger)
	if err != nil {
		return Unchanged, fmt.Errorf("failed to check certificate on disk: %w", err)
	}

	if state == Unchanged && !configuration.Force {
		logger.Info("File not changed, skipping...", "path", c.FilePath)
		return Unchanged, nil
	}

	if configuration.Force {
		logger.Info("Forcing file system change due to --force", "name", c.Name)
	}

	// --force rewrites the file even though the bytes are identical, and has
	// always reported that as a change. Keep it: a forced run is meant to be
	// loud, and callers already treat --force as "everything moved".
	if state == Unchanged {
		state = Modified
	}

	// Commit logs what it published, and this is the only place that still
	// knows whether the target existed beforehand.
	c.state = state

	if configuration.DryRun {
		// A dry run stages nothing, so there is nothing for Commit to publish
		// or for Abort to remove.
		logger.Info("DRY-RUN: skipping file write", "path", c.FilePath, "file-type", c.Type)
		return state, nil
	}

	if err := c.writeTempFile(logger); err != nil {
		return Unchanged, fmt.Errorf("failed to handle certificate: %w", err)
	}

	return state, nil
}

// Commit is phase 2 of a rollout: it renames the staged file over the target,
// which is the point where the new content becomes visible to everything else
// on the machine. A single rename is atomic, so no reader ever sees a partial
// file.
//
// Committing an artefact that staged nothing is a no-op, so it can be called
// for every artefact of a certificate unconditionally.
//
// Returns error or nil on success.
func (c *GenericCertificate) Commit(logger *slog.Logger) error {
	if c.tempPath == "" {
		return nil
	}

	if err := os.Rename(c.tempPath, c.FilePath); err != nil {
		return fmt.Errorf("failed to replace target file with temporary file: %w", err)
	}

	// handed over to the filesystem, there is nothing left for Abort to remove
	c.tempPath = ""

	// Publishing is the moment worth reporting, and the state recorded by
	// Prepare is what tells a first deployment from a renewal (#31).
	if c.state == Created {
		logger.Info("New file deployed", "path", c.FilePath, "file-type", c.Type)
	} else {
		logger.Info("File updated", "path", c.FilePath, "file-type", c.Type)
	}

	return nil
}

// Abort is phase 2' of a rollout: it throws the staged file away and leaves the
// target untouched.
//
// It is a no-op for an artefact that staged nothing and for one that was
// already committed, so it is safe to defer for every artefact of a
// certificate. A failure to remove the temporary file is logged rather than
// returned: the run has already decided not to deploy this certificate, and a
// leftover file in the target directory must not turn into a second failure.
func (c *GenericCertificate) Abort(logger *slog.Logger) {
	if c.tempPath == "" {
		return
	}

	if err := os.Remove(c.tempPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		logger.Error("failed to clean up temporary file", "path", c.tempPath, "error", err)
	}

	logger.Debug("Discarded staged file", "path", c.FilePath, "temp-path", c.tempPath)
	c.tempPath = ""
}

// readFromDisk reads file data from disk and populates the data []byte field.
//
// Returns error or nil on success
func (c *GenericCertificate) readFromDisk() error {
	filebytes, err := os.ReadFile(c.FilePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return err
		} else {
			return fmt.Errorf("failed to read file from disk: %w", err)
		}
	}

	c.diskBytes = filebytes
	return nil
}

// needsRollout checks the data []bytes against the data on disk.
//
// Returns the state the file would end up in: Created if there is no file yet,
// Modified if there is one with different content, Unchanged otherwise.
func (c *GenericCertificate) needsRollout(logger *slog.Logger) (RolloutState, error) {
	err := c.readFromDisk()

	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			logger.Debug("No file on disk yet", "path", c.FilePath)
			return Created, nil
		} else {
			return Unchanged, fmt.Errorf("failed to compare data to file on disk: %w", err)
		}
	}

	diskHash := sha256.Sum256(c.diskBytes)
	serverHash := sha256.Sum256(c.serverBytes)

	if diskHash != serverHash {
		logger.Debug("File on disk differs from server source", "path", c.FilePath)
		return Modified, nil
	}

	logger.Debug("File on disk is identical to server source", "path", c.FilePath)
	return Unchanged, nil
}

// tempFilePattern is the os.CreateTemp pattern for staged files. The leading
// dot keeps them out of the way of shell globs while they exist, and the fixed
// prefix makes leftovers from a killed run recognisable.
const tempFilePattern = ".certwarden-deploy-*"

// writeTempFile stages the certificate data as a temporary file next to its
// target: it writes, chmods and fsyncs the new content, but does not publish
// it. Committing the result is up to Commit.
//
// The temporary file is created in the target directory rather than in the
// system temp dir, so that the rename in Commit stays inside one filesystem
// and is therefore atomic.
//
// Returns error or nil on success.
func (c *GenericCertificate) writeTempFile(logger *slog.Logger) error {
	dir := filepath.Dir(c.FilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	mode := fs.FileMode(0644)
	if stat, err := os.Stat(c.FilePath); err == nil {
		mode = stat.Mode().Perm()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to inspect file before writing: %w", err)
	}

	file, err := os.CreateTemp(dir, tempFilePattern)
	if err != nil {
		return fmt.Errorf("failed to open temporary file for writing: %w", err)
	}

	// From here on the file belongs to the abort guard in rolloutCertificate:
	// every path out of this function leaves it recorded in tempPath, so it is
	// removed unless it gets committed.
	c.tempPath = file.Name()

	closeAfterError := func(stage string) {
		if closeErr := file.Close(); closeErr != nil {
			logger.Error(
				"failed to close temporary file after error", "path", c.tempPath,
				"stage", stage, "error", closeErr,
			)
		}
	}

	if err := file.Chmod(mode); err != nil {
		closeAfterError("chmod")
		return fmt.Errorf("failed to set temporary file permissions: %w", err)
	}

	w := bufio.NewWriter(file)

	if _, err := w.Write(c.serverBytes); err != nil {
		closeAfterError("write")
		return fmt.Errorf("failed to write data to file: %w", err)
	}

	if err = w.Flush(); err != nil {
		closeAfterError("flush")
		return fmt.Errorf("failed to flush data to file: %w", err)
	}

	if err = file.Sync(); err != nil {
		closeAfterError("sync")
		return fmt.Errorf("failed to sync data to file: %w", err)
	}

	if err = file.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	logger.Debug("Successfully staged file", "path", c.FilePath, "temp-path", c.tempPath)
	return nil
}

// fetchFromServer fetches the cert/key data from the CertWarden server and
// fills the serverBytes field.
//
// Returns error or nil on success.
func (c *GenericCertificate) fetchFromServer(logger *slog.Logger, baseUrl string, skipInsecure bool) error {
	var apiPath string

	switch c.Type {
	case CertificateFile:
		apiPath = constants.CertificateApiPath
	case KeyFile:
		apiPath = constants.KeyApiPath
	case CaCertificateFile:
		apiPath = constants.CaCertificateApiPath
	case PrivateCertFile:
		apiPath = constants.PrivateCertApiPath
	case PrivateCertChainFile:
		apiPath = constants.PrivateCertChainApiPath
	default:
		return fmt.Errorf("unsupported file type: %v", c.Type)
	}

	requestURL := baseUrl + apiPath + c.Name

	// pem is the server default, so it is never sent: an unchanged config must
	// keep producing the exact same request it did before formats existed.
	//
	// WARNING, UNVERIFIED: pkcs12 and jks ask CertWarden to build a container
	// around the certificate. If the server generates that container per
	// request with a fresh salt/IV, the returned bytes differ on every run even
	// when the certificate itself did not change. Change detection here is a
	// SHA-256 over the response body, so in that case every run would look
	// changed and the configured action would fire on every timer tick.
	//
	// This has not been verified against a live CertWarden instance. If it
	// turns out to be true, change detection for the non-pem formats needs to
	// move off the raw bytes (for example onto the parsed certificate's
	// serial or notAfter) rather than being papered over here.
	// See TestFetchFromServerAssumesDeterministicBinaryBodies.
	if c.Format != "" && c.Format != constants.FormatPEM {
		requestURL += "?format=" + url.QueryEscape(c.Format)
	}

	logger.Debug("Data request URL: "+requestURL, "file-type", c.Type)
	var transport http.RoundTripper

	if skipInsecure {
		logger.Debug("Upstream Server TLS Certificate Validation is disabled")
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		logger.Debug("Upstream Server HTTP TLS Certificate Validation is enabled")
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return fmt.Errorf("failed to prepare to request data from server: %w", err)
	}

	c.applyHeaders(logger, req)

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to request data from server: %w", err)
	}

	defer func(l *slog.Logger) {
		if err := res.Body.Close(); err != nil {
			l.Error("failed to close http response body", "error", err)
		}
	}(logger)

	if res.StatusCode == http.StatusUnauthorized {
		body := errorBodyForLog(res)
		logger.Error(
			"API-Key for request is invalid, skipping certificate!",
			appendBodyArg([]any{"name", c.Name, "file-type", c.Type}, body)...,
		)
		if body == "" {
			return errors.New("API-Key invalid")
		}
		return fmt.Errorf("API-Key invalid: %v", body)
	} else if res.StatusCode != http.StatusOK {
		body := errorBodyForLog(res)
		logger.Error(
			"failed to get data from server",
			appendBodyArg([]any{"name", c.Name, "http-response", res.Status, "file-type", c.Type}, body)...,
		)
		if body == "" {
			return fmt.Errorf("got non-success error code from server: %v", res.Status)
		}
		return fmt.Errorf("got non-success error code from server: %v: %v", res.Status, body)
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read response from server: %w", err)
	}

	c.serverBytes = bodyBytes
	return nil
}

// applyHeaders sets the headers for a request to the CertWarden server.
//
// The configured custom headers go on first and the headers this tool owns go on
// afterwards, which is what makes X-API-Key impossible to override from the
// config: a typo in the http block turning every request into a 401 would be a
// miserable thing to debug. User-Agent is protected the same way.
//
// Only header names are logged. The values are typically access tokens.
func (c *GenericCertificate) applyHeaders(logger *slog.Logger, req *http.Request) {
	if len(c.HTTP.Headers) > 0 {
		names := make([]string, 0, len(c.HTTP.Headers))

		for name, value := range c.HTTP.Headers {
			req.Header.Set(name, value)
			names = append(names, name)
		}

		slices.Sort(names)
		logger.Debug("Applying custom HTTP headers", "file-type", c.Type, "header-names", names)
	}

	req.Header.Set("User-Agent", constants.UserAgent)
	req.Header.Set(constants.ApiKeyHeaderName, c.Secret)
}

// maxLoggedBodyBytes caps how much of an error response body is read for
// logging, so a verbose upstream error page cannot flood the log.
const maxLoggedBodyBytes = 4 << 10

// errorBodyForLog reads a bounded prefix of a response body and normalises it
// into a single-line string that can be attached to a log record or an error.
//
// It must only ever be called on non-success responses: on success the body is
// the certificate/key material itself and must never be logged.
//
// Returns an empty string if the body is empty, unreadable or not textual.
func errorBodyForLog(res *http.Response) string {
	mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil {
		return ""
	}

	isTextual := strings.HasPrefix(mediaType, "text/") ||
		mediaType == "application/json" ||
		mediaType == "application/problem+json"
	if !isTextual {
		return ""
	}

	// read one byte past the cap so we can tell a full body from a truncated one
	bodyBytes, err := io.ReadAll(io.LimitReader(res.Body, maxLoggedBodyBytes+1))
	if err != nil {
		return ""
	}

	truncated := len(bodyBytes) > maxLoggedBodyBytes
	if truncated {
		bodyBytes = bodyBytes[:maxLoggedBodyBytes]
	}

	// collapse newlines and whitespace runs so the log record stays on one line
	body := strings.Join(strings.Fields(string(bodyBytes)), " ")
	if body == "" {
		return ""
	}

	if truncated {
		body += " [truncated]"
	}

	return body
}

// appendBodyArg appends the server response body to a set of slog arguments,
// omitting it entirely when there is no usable body to report.
func appendBodyArg(args []any, body string) []any {
	if body == "" {
		return args
	}

	return append(args, "response-body", body)
}

// maxActionOutputBytes is the maximum amount of output captured per stream from
// a post-rollout action. Anything beyond it is dropped so that a runaway action
// cannot exhaust memory or flood the journal.
const maxActionOutputBytes = 64 * 1024

// actionOutputTruncationMarker is appended to captured output that hit maxActionOutputBytes.
const actionOutputTruncationMarker = "... [truncated]"

// boundedBuffer is an io.Writer that keeps at most limit bytes and discards the
// rest, while remembering that output was dropped.
type boundedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

// Write stores as much of p as the limit allows and reports a full write, so a
// command is never blocked by the cap.
func (b *boundedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.buf.Len()
	if remaining <= 0 {
		if len(p) > 0 {
			b.truncated = true
		}
		return len(p), nil
	}

	if len(p) > remaining {
		b.buf.Write(p[:remaining])
		b.truncated = true
		return len(p), nil
	}

	b.buf.Write(p)
	return len(p), nil
}

// String returns the captured output without trailing newlines, marked as
// truncated if the limit was reached.
func (b *boundedBuffer) String() string {
	out := strings.TrimRight(b.buf.String(), "\n")
	if b.truncated {
		out += actionOutputTruncationMarker
	}
	return out
}

// actionCommand turns an Action into the command to execute.
//
// The two YAML forms map onto two very different executions, and this is the
// only place that difference exists:
//
//   - list form: exec the binary directly, arguments are passed through
//     verbatim and no shell ever sees them
//   - string form: hand the whole string to `sh -c`, so operators, quoting and
//     redirects mean what the user wrote
//
// Reports false when there is nothing to run.
func actionCommand(action configuration.Action) (*exec.Cmd, bool) {
	if action.IsEmpty() {
		return nil, false
	}

	if len(action.Args) > 0 {
		return exec.Command(action.Args[0], action.Args[1:]...), true
	}

	return exec.Command(configuration.ShellPath, "-c", action.Command), true
}

// handleCertificateAction executes the user-defined action after successful certificate deployment
func handleCertificateAction(logger *slog.Logger, certAction configuration.Action) error {
	cmd, runnable := actionCommand(certAction)
	if !runnable {
		return nil
	}

	action := certAction.String()

	stdout := &boundedBuffer{limit: maxActionOutputBytes}
	stderr := &boundedBuffer{limit: maxActionOutputBytes}

	cmd.Stdout = stdout
	cmd.Stderr = stderr

	logger.Debug("Executing post-rollout action", "command", action)

	err := cmd.Run()

	// stderr is worth surfacing even on success, tools warn there and still exit 0
	if stderrOutput := stderr.String(); stderrOutput != "" {
		logger.Error("Post-rollout action wrote to stderr", "command", action, "stderr", stderrOutput)
	}

	stdoutOutput := stdout.String()

	if err != nil {
		logArgs := []any{"command", action}

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			logArgs = append(logArgs, "exit-code", exitErr.ExitCode())
		}
		if stdoutOutput != "" {
			logArgs = append(logArgs, "stdout", stdoutOutput)
		}
		logArgs = append(logArgs, "error", err)

		logger.Error("Post-rollout action failed", logArgs...)
		return err
	}

	if stdoutOutput != "" {
		logger.Debug("Post-rollout action stdout", "command", action, "stdout", stdoutOutput)
	}

	return nil
}
