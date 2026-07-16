package configuration

// RunOnPolicy decides when a certificate's post-rollout action is executed.
//
// It is only about the action. Which files are written is decided by the
// content on disk and by --force, never by run_on.
type RunOnPolicy string

const (
	// RunOnNew runs the action only when an artefact did not exist on disk
	// before this run, e.g. to enrol a brand new certificate somewhere.
	RunOnNew RunOnPolicy = "new"

	// RunOnChanged runs the action only when an artefact existed and its
	// content differed, e.g. a plain reload on renewal.
	RunOnChanged RunOnPolicy = "changed"

	// RunOnNewOrChanged runs the action whenever anything was written. This is
	// the default and the historical behaviour.
	RunOnNewOrChanged RunOnPolicy = "new_or_changed"

	// RunOnAll runs the action on every run, even when nothing was written.
	RunOnAll RunOnPolicy = "all"
)

// DefaultRunOn is the policy used when run_on is omitted.
//
// It must stay RunOnNewOrChanged: that is what the tool did before run_on
// existed, so every config that does not mention run_on keeps behaving
// exactly as it did.
const DefaultRunOn = RunOnNewOrChanged

// IsValid reports whether the policy is one this tool knows.
//
// An unknown value is rejected at startup rather than skipped: silently
// falling back to a default would mean an action that quietly never runs, or
// one that quietly runs too often.
func (p RunOnPolicy) IsValid() bool {
	switch p {
	case RunOnNew, RunOnChanged, RunOnNewOrChanged, RunOnAll:
		return true
	}

	return false
}

// EffectiveRunOn returns the certificate's run_on policy, applying the default
// for an omitted key.
func (c CertificateData) EffectiveRunOn() RunOnPolicy {
	if c.RunOn == "" {
		return DefaultRunOn
	}

	return RunOnPolicy(c.RunOn)
}
