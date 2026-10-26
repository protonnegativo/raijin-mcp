package update

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Table writes the report as a compact table (an engine's target is marked when it is the version the
// tools were tested with rather than the latest), then the commands to run by hand, why a downgrade is
// needed, which tool set a tested version the tools disagree on, and the errors. Forced, a last line
// says when an untested engine is installed or proposed.
func (r *Report) Table(w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tINSTALLED\tLATEST\tACTION")
	var manual []string
	for _, it := range r.Items {
		tv := orDash(it.Target)
		if it.Tested {
			tv += " (tested)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", it.Name, installed(it), tv, it.status())
		if it.Action == "manual" {
			manual = append(manual, it.Name+": "+it.Command)
		}
	}
	tw.Flush()
	if len(manual) > 0 {
		fmt.Fprintln(w, "\nrun by hand:")
		for _, m := range manual {
			fmt.Fprintln(w, "  "+m)
		}
	}
	for _, it := range r.Items {
		switch {
		case it.Action != "downgrade":
		case it.Reason != "":
			fmt.Fprintf(w, "%s: %s is not accepted; %s\n", it.Name, it.Installed, it.Reason)
		default:
			fmt.Fprintf(w, "%s: %s is newer than the tested %s (--force keeps it)\n", it.Name, it.Installed, it.Target)
		}
	}
	for _, it := range r.Items {
		if it.TestedBy != "" {
			fmt.Fprintf(w, "%s: %s\n", it.Name, it.TestedBy)
		}
	}
	for _, it := range r.Items {
		if it.Err != "" {
			fmt.Fprintf(w, "%s: %s\n", it.Name, it.Err)
		}
	}
	for _, e := range r.Errors {
		fmt.Fprintf(w, "error: %s: %s\n", e.Target, e.Hint)
	}
	fmt.Fprintln(w, r.summary())
	if r.Force && r.untested() {
		fmt.Fprintln(w, "--force: engines at the latest version, not tested with Raijin")
	}
}

// untested is true when an engine other than the tested version is installed or proposed.
func (r *Report) untested() bool {
	for _, it := range r.Items {
		switch {
		case it.Kind != "engine" || it.SystemOK:
		case it.Action != "" && !it.Tested,
			it.Installed != "" && Compare(it.Installed, it.engine.Version) != 0:
			return true
		}
	}
	return false
}

func installed(it *Item) string {
	switch {
	case it.Path == "":
		return "missing"
	case it.Installed == "":
		return "?"
	}
	return it.Installed
}

// status is the ACTION column: what Check plans, or what Apply did.
func (it *Item) status() string {
	switch {
	case it.Result != "":
		return it.Result
	case it.Unknown:
		return "version unknown"
	case it.SystemOK:
		return "ok (system)"
	case it.Action == "":
		return "up to date"
	case it.Action == "manual":
		return "run by hand (below)"
	}
	return it.Action
}

func (r *Report) summary() string {
	n := r.Outdated()
	switch {
	case len(r.Items) == 0:
		return "no Raijin tools found (--bin-dir, then PATH)"
	case n == 0:
		return fmt.Sprintf("%d up to date", len(r.Items))
	case r.Applied:
		done := 0
		for _, it := range r.Items {
			if it.Result == "updated" {
				done++
			}
		}
		return fmt.Sprintf("%d of %d updated", done, n)
	}
	return fmt.Sprintf("%d of %d out of date", n, len(r.Items))
}

type finding struct {
	Severity  string   `json:"severity"`
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Installed string   `json:"installed"`
	Latest    string   `json:"latest,omitempty"`
	Tested    string   `json:"tested,omitempty"`
	Action    string   `json:"action"`
	Command   string   `json:"command,omitempty"`
	Result    string   `json:"result,omitempty"`
	Error     string   `json:"error,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	TestedBy  string   `json:"tested_by,omitempty"`
	UsedBy    []string `json:"used_by,omitempty"`
}

type group struct {
	Kind  string   `json:"kind"`
	Items []string `json:"items"`
}

// JSON is the report in the shape of a Raijin Schema result: findings are what is (or was) out of
// date, groups what needs nothing. next is the follow-up suggested when something is out of date.
func (r *Report) JSON(ver, next string) []byte {
	out := struct {
		Tool     string    `json:"tool"`
		Version  string    `json:"version"`
		Summary  string    `json:"summary"`
		Findings []finding `json:"findings"`
		Groups   []group   `json:"groups,omitempty"`
		Errors   []Error   `json:"errors,omitempty"`
		Next     []string  `json:"next,omitempty"`
	}{Tool: "raijin-update", Version: ver, Summary: r.summary(), Findings: []finding{}, Errors: r.Errors}
	var ok, unknown []string
	for _, it := range r.Items {
		switch {
		case it.Unknown:
			unknown = append(unknown, it.Name)
		case it.Action == "":
			ok = append(ok, it.Name+" "+it.Installed)
		default:
			f := finding{Severity: "low", Kind: it.Kind, Name: it.Name, Installed: installed(it), Action: it.Action,
				Command: it.Command, Result: it.Result, Error: it.Err, Reason: it.Reason, TestedBy: it.TestedBy, UsedBy: it.UsedBy}
			if it.Tested {
				f.Tested = it.Target
			} else {
				f.Latest = it.Target
			}
			out.Findings = append(out.Findings, f)
		}
	}
	if len(ok) > 0 {
		out.Groups = append(out.Groups, group{"up_to_date", ok})
	}
	if len(unknown) > 0 {
		out.Groups = append(out.Groups, group{"version_unknown", unknown})
	}
	switch {
	case r.Applied && r.Outdated() > 0:
		out.Next = []string{"restart raijin-mcp so it loads the updated tools"}
	case !r.Applied && r.Outdated() > 0 && next != "":
		out.Next = []string{next}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(out)
	return bytes.TrimSpace(b.Bytes())
}

// ParseVerbs splits "scan,raijin-probe" into verbs.
func ParseVerbs(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimPrefix(strings.TrimSpace(v), "raijin-"); v != "" {
			out = append(out, v)
		}
	}
	return out
}
