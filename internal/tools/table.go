package tools

// Param is one tool argument and the CLI flag it becomes.
type Param struct {
	Name string // JSON property
	Flag string // CLI flag, without dashes
	Type string // string, integer, boolean or array (of strings)
	Desc string
}

// Scope rules for a tool.
const (
	ScopeRequired = iota // --scope must be given; the server refuses the call without it
	ScopeOptional        // passed when given
	ScopeNone            // the tool takes no scope
)

// Spec describes one Raijin binary. Descriptions are short on purpose: every word here is paid
// for in the agent's context each time it lists the tools.
type Spec struct {
	Verb       string
	Desc       string
	Active     bool     // sends traffic to the targets; scope is always required
	Scope      int      // ScopeRequired, ScopeOptional or ScopeNone
	Targets    []string // flags that take the targets, in order of preference; the first one the binary has is used
	TargetDesc string
	Input      bool   // has --input (replay engine output instead of running the engine)
	ScopeDesc  string // overrides the scope description (raijin-secrets scopes paths, not hosts)
	Engine     string // engine that receives engine_args after --; empty for none
	Positional *Param // arguments passed after the flags (raijin-diff's two files)
	Params     []Param
}

var (
	rate    = Param{"rate", "rate", "integer", "requests/s"}
	timeout = Param{"timeout", "timeout", "integer", "seconds per request"}
)

// Table lists every Raijin tool the server knows. A binary that is not on PATH is not exposed, and
// a param whose flag the installed binary does not have (per its -h) is dropped, so entries for
// tools still in development stay safe when their flags change.
var Table = []Spec{
	{
		Verb: "scan", Desc: "nuclei scan: findings ranked by severity, every location; info matches grouped.",
		Active: true, Targets: []string{"u"}, TargetDesc: "URLs or hosts", Input: true, Engine: "nuclei",
		Params: []Param{
			{"templates", "t", "array", "template files or dirs"},
			{"tags", "tags", "string", "e.g. cve,exposure"},
			{"severity", "severity", "string", "e.g. critical,high"},
			{"include_info", "include-info", "boolean", "info matches as findings"},
			rate, timeout,
		},
	},
	{
		Verb: "probe", Desc: "httpx probe: status, title, tech per URL; identical responses grouped, panels/errors/outliers ranked.",
		Active: true, Targets: []string{"u"}, TargetDesc: "URLs or hosts", Input: true, Engine: "httpx",
		Params: []Param{
			{"follow", "follow", "boolean", "follow same-host redirects"},
			rate, timeout,
		},
	},
	{
		Verb: "subs", Desc: "Passive subdomain enumeration (subfinder+dnsx): live names grouped by IP/CNAME, dangling CNAMEs flagged.",
		Scope: ScopeRequired, Targets: []string{"d"}, TargetDesc: "root domains", Input: true, Engine: "subfinder",
		Params: []Param{
			{"no_resolve", "no-resolve", "boolean", "skip dnsx"},
			{"max_time", "max-time", "integer", "minutes"},
		},
	},
	{
		Verb: "ports", Desc: "Port scan (naabu+nmap): open ports grouped by service, unusual ports flagged.",
		Active: true, Targets: []string{"host"}, TargetDesc: "hosts, IPs or CIDRs", Input: true, Engine: "naabu",
		Params: []Param{
			{"ports", "p", "string", "e.g. 22,80,8000-8100"},
			{"top_ports", "top-ports", "string", "100, 1000 or full"},
			{"no_services", "no-services", "boolean", "skip nmap"},
			{"rate", "rate", "integer", "packets/s"},
		},
	},
	{
		Verb: "crawl", Desc: "katana crawl: unique endpoints and params, collapsed by route pattern.",
		Active: true, Targets: []string{"u"}, TargetDesc: "start URLs", Input: true, Engine: "katana",
		Params: []Param{
			{"depth", "depth", "integer", "default 3"},
			{"duration", "duration", "string", "per target, e.g. 2m"},
			rate, timeout,
		},
	},
	{
		Verb: "js", Desc: "JS analysis: endpoints, API routes and secrets from JS bundles, deduped across files.",
		Active: true, Targets: []string{"u"}, TargetDesc: "page or JS URLs", Input: true, Engine: "katana",
		Params: []Param{rate, timeout},
	},
	{
		Verb: "params", Desc: "Hidden HTTP parameters (arjun) that change the response.",
		Active: true, Targets: []string{"u"}, TargetDesc: "URLs", Input: true, Engine: "arjun",
		Params: []Param{
			{"method", "method", "string", "GET, POST, JSON or XML, comma-separated"},
			{"wordlist", "wordlist", "string", "file, or small, medium, large"},
			rate, timeout,
		},
	},
	{
		Verb: "fuzz", Desc: "ffuf content discovery: only responses that differ from the baseline.",
		Active: true, Targets: []string{"u"}, TargetDesc: "URLs with FUZZ", Input: true, Engine: "ffuf",
		Params: []Param{{"wordlist", "w", "string", "wordlist path"}, rate, timeout},
	},
	{
		Verb: "tls", Desc: "TLS audit (tlsx): weak protocols/ciphers and cert issues, grouped by issue.",
		Active: true, Targets: []string{"u", "host"}, TargetDesc: "hosts, host:port or CIDRs", Input: true, Engine: "tlsx",
		Params: []Param{
			{"ports", "p", "string", "default 443"},
			{"no_enum", "no-enum", "boolean", "skip version/cipher enumeration"},
			timeout,
		},
	},
	{
		// No engine_args and no --verify: verification sends each secret to its provider, which is
		// the operator's call, not the agent's.
		Verb: "secrets", Desc: "Secret scan (trufflehog) of local paths and git repos: one finding per secret, minimal context.",
		Targets: []string{"p"}, TargetDesc: "local paths", Input: true,
		ScopeDesc: "authorized paths and repo URLs (prefix*), !excluded",
		Params: []Param{
			{"repos", "g", "array", "git repos (URL or path), history included"},
			{"no_context", "no-context", "boolean", "skip reading the source line"},
		},
	},
	{
		Verb: "xss", Desc: "XSS check (dalfox): confirmed reflections with payload and context.",
		Active: true, Targets: []string{"u"}, TargetDesc: "URLs with params", Input: true, Engine: "dalfox",
		Params: []Param{rate, timeout},
	},
	{
		Verb: "cors", Desc: "Exploitable CORS only (credentials + reflected/null origin), with the proof request.",
		Active: true, Targets: []string{"u"}, TargetDesc: "URLs", Input: true,
		Params: []Param{{"headers", "H", "array", "extra headers \"Name: value\""}, rate, timeout},
	},
	{
		Verb: "takeover", Desc: "Subdomain takeover: dangling records with provider and claim hint.",
		Scope: ScopeRequired, Targets: []string{"d", "u", "host"}, TargetDesc: "hostnames", Input: true, Engine: "dnsx",
	},
	{
		Verb: "diff", Desc: "What changed between two Raijin outputs of the same tool.",
		Scope:      ScopeNone,
		Positional: &Param{"files", "", "array", "old and new output files"},
	},
}

// Lookup returns the spec for a verb.
func Lookup(verb string) (Spec, bool) {
	for _, s := range Table {
		if s.Verb == verb {
			return s, true
		}
	}
	return Spec{}, false
}
