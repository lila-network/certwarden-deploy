package configuration

import (
	"fmt"
	"strings"
)

// ShellPath is the shell used to run the string form of an action.
//
// The string form is handed to it as `sh -c <action>`, which is what makes
// pipes, redirects, `&&` chains and quoting work at all.
//
// Running a config value through a shell is safe here because the config file
// is trusted input: it is root-owned and mode 600 by convention, so anyone who
// can write it can already run arbitrary commands as the service user. The
// shell does not widen that boundary, it only makes the existing one usable.
const ShellPath = "/bin/sh"

// Action is the command executed after a certificate rollout.
//
// It accepts two YAML forms:
//
//	# string form, run through the shell
//	action: "cp {cert_path} /etc/ssl/ && systemctl reload nginx"
//
//	# list form, executed directly without a shell
//	action:
//	  - /usr/bin/systemctl
//	  - reload
//	  - nginx
//
// The string form is the ergonomic one and keeps every pre-existing config
// working unchanged. The list form is the explicit one: no shell is involved,
// so no quoting rules apply and arguments containing spaces stay single
// arguments.
type Action struct {
	// Command is the string form of the action, executed via ShellPath.
	// Empty when the list form was used.
	Command string

	// Args is the list form of the action, executed directly. Args[0] is the
	// binary, the rest are passed through untouched. Nil for the string form.
	Args []string

	// set records whether the action key was present in the config file at
	// all. An omitted action is fine (nothing to run), an action that is
	// present but empty is a config mistake and is rejected by IsValid.
	set bool
}

// ShellAction builds an Action in string form, as if it had been read from a
// scalar `action:` key.
func ShellAction(command string) Action {
	return Action{Command: command, set: true}
}

// ExecAction builds an Action in list form, as if it had been read from a
// sequence `action:` key.
func ExecAction(args ...string) Action {
	return Action{Args: args, set: true}
}

// UnmarshalYAML reads either a scalar or a sequence into an Action.
//
// It implements yaml.InterfaceUnmarshaler. The scalar form is attempted first
// because it is by far the common case, and a sequence never decodes into a
// string.
func (a *Action) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var command string
	if err := unmarshal(&command); err == nil {
		*a = Action{Command: command, set: true}
		return nil
	}

	var args []string
	if err := unmarshal(&args); err != nil {
		return fmt.Errorf("failed to parse 'action': it must be a string or a list of strings: %w", err)
	}

	*a = Action{Args: args, set: true}
	return nil
}

// MarshalYAML renders an action back in the form it was written in.
//
// It implements yaml.InterfaceMarshaler, and exists for `config show`: without
// it the action would be dumped as the struct behind it, which is neither what
// the user wrote nor something they could paste back into a config file.
func (a Action) MarshalYAML() (interface{}, error) {
	if a.Args != nil {
		return a.Args, nil
	}

	return a.Command, nil
}

// IsSet reports whether an action key was present in the config file.
//
// It says nothing about whether the action is runnable, only whether the user
// wrote the key at all. Use IsEmpty for that.
func (a Action) IsSet() bool {
	return a.set
}

// IsEmpty reports whether the action has nothing to execute.
func (a Action) IsEmpty() bool {
	if len(a.Args) > 0 {
		return false
	}

	return strings.TrimSpace(a.Command) == ""
}

// String renders the action for log output.
//
// The list form is joined with spaces, which is good enough to identify a
// command in a log record but is not a shell-quoted round trip.
func (a Action) String() string {
	if len(a.Args) > 0 {
		return strings.Join(a.Args, " ")
	}

	return a.Command
}

// substitute returns a copy of the action with every placeholder replaced.
//
// Both forms are substituted: in the string form the whole command is
// rewritten, in the list form every argument is rewritten on its own so a
// placeholder can be a complete argument.
func (a Action) substitute(replace func(string) string) Action {
	out := Action{Command: replace(a.Command), set: a.set}

	if a.Args != nil {
		out.Args = make([]string, len(a.Args))
		for index, arg := range a.Args {
			out.Args[index] = replace(arg)
		}
	}

	return out
}

// ActionsEnabled reports whether post-rollout actions may run at all.
//
// The default is on, and it must stay on: certwarden-deploy configs exist in
// the wild whose whole point is the reload they trigger, and defaulting to off
// would silently turn every one of them into a file copier. Actions are only
// skipped when the user says so, either with actions.enabled: false or with
// --no-actions.
//
// --no-actions wins over the config file: a flag is the more immediate
// statement of intent, and it is the escape hatch for a config you do not want
// to edit.
func (c *ConfigFileData) ActionsEnabled() bool {
	if NoActions {
		return false
	}

	if c.Actions.Enabled != nil {
		return *c.Actions.Enabled
	}

	return true
}
