// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/gobwas/glob"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"

	"github.com/ory/oathkeeper/driver/configuration"
)

type Match struct {
	// An array of HTTP methods (e.g. GET, POST, PUT, DELETE, ...). When ORY Oathkeeper searches for rules
	// to decide what to do with an incoming request to the proxy server, it compares the HTTP method of the incoming
	// request with the HTTP methods of each rules. If a match is found, the rule is considered a partial match.
	// If the matchesUrl field is satisfied as well, the rule is considered a full match.
	Methods []string `json:"methods"`

	// This field represents the URL pattern this rule matches. When ORY Oathkeeper searches for rules
	// to decide what to do with an incoming request to the proxy server, it compares the full request URL
	// (e.g. https://mydomain.com/api/resource) without query parameters of the incoming
	// request with this field. If a match is found, the rule is considered a partial match.
	// If the matchesMethods field is satisfied as well, the rule is considered a full match.
	//
	// You can use regular expressions or glob patterns in this field to match more than one url.
	// The matching strategy is determined by configuration parameter MatchingStrategy.
	// Regular expressions and glob patterns are encapsulated in brackets < and >.
	// The following regexp example matches all paths of the domain `mydomain.com`: `https://mydomain.com/<.*>`.
	// The glob equivalent of the above regexp example is `https://mydomain.com/<*>`.
	URL        string `json:"url"`
	isComposed bool
}

func (m *Match) GetURL() string       { return m.URL }
func (m *Match) GetMethods() []string { return m.Methods }
func (m *Match) Protocol() Protocol   { return ProtocolHTTP }

type MatchGRPC struct {
	Authority  string `json:"authority"`
	FullMethod string `json:"full_method"`
}

func (m *MatchGRPC) GetURL() string {
	return fmt.Sprintf("grpc://%s/%s", m.Authority, m.FullMethod)
}
func (m *MatchGRPC) GetMethods() []string { return []string{"POST"} }
func (m *MatchGRPC) Protocol() Protocol   { return ProtocolGRPC }

type Handler struct {
	// Handler identifies the implementation which will be used to handle this specific request. Please read the user
	// guide for a complete list of available handlers.
	Handler string `json:"handler"`

	// Config contains the configuration for the handler. Please read the user
	// guide for a complete list of each handler's available settings.
	Config json.RawMessage `json:"config"`
}

type ErrorHandler struct {
	// Handler identifies the implementation which will be used to handle this specific request. Please read the user
	// guide for a complete list of available handlers.
	Handler string `json:"handler"`

	// Config defines additional configuration for the response handler.
	Config json.RawMessage `json:"config"`
}

type OnErrorRequest struct {
	// ContentType defines the content type(s) that should match. Wildcards such as `application/*` are supported.
	ContentType []string `json:"content_type"`

	// Accept defines the accept header that should match. Wildcards such as `application/*` are supported.
	Accept []string `json:"accept"`
}

type URLProvider interface {
	GetURL() string
	GetMethods() []string
	Protocol() Protocol
}

// Rule is a single rule that will get checked on every HTTP request.
type Rule struct {
	// ID is the unique id of the rule. It can be at most 190 characters long, but the layout of the ID is up to you.
	// You will need this ID later on to update or delete the rule.
	ID string `json:"id"`

	// Version represents the access rule version. Should match one of ORY Oathkeepers release versions. Supported since
	// v0.20.0-beta.1+oryOS.14.
	Version string `json:"version"`

	// Description is a human readable description of this rule.
	Description string `json:"description"`

	// Match defines the URL that this rule should match.
	Match URLProvider `json:"match" faker:"urlProvider"`

	// Authenticators is a list of authentication handlers that will try and authenticate the provided credentials.
	// Authenticators are checked iteratively from index 0 to n and if the first authenticator to return a positive
	// result will be the one used.
	//
	// If you want the rule to first check a specific authenticator  before "falling back" to others, have that authenticator
	// as the first item in the array.
	Authenticators []Handler `json:"authenticators"`

	// Authorizer is the authorization handler which will try to authorize the subject (authenticated using an Authenticator)
	// making the request.
	Authorizer Handler `json:"authorizer"`

	// Mutators is a list of mutation handlers that transform the HTTP request. A common use case is generating a new set
	// of credentials (e.g. JWT) which then will be forwarded to the upstream server.
	//
	// Mutations are performed iteratively from index 0 to n and should all succeed in order for the HTTP request to be forwarded.
	Mutators []Handler `json:"mutators"`

	// Errors is a list of error handlers. These will be invoked if any part of the system returns an error. You can
	// configure error matchers to listen on certain errors (e.g. unauthorized) and execute specific logic (e.g. redirect
	// to the login endpoint, return with an XML error, return a json error, ...).
	Errors []ErrorHandler `json:"errors"`

	// Upstream is the location of the server where requests matching this rule should be forwarded to.
	Upstream Upstream `json:"upstream"`

	matchingEngine        MatchingEngine
	requiresComposed      bool
	composedRegexpPattern string
	composedGlobPattern   string
	composedRawURL        json.RawMessage
}

type composedURL struct {
	Base       string             `json:"base"`
	Paths      []composedURLPath  `json:"paths"`
	PathParams []composedURLParam `json:"path_params"`
}

type composedURLPath struct {
	Prefix   string              `json:"prefix"`
	Branches []composedURLBranch `json:"branches"`
}

type composedURLBranch struct {
	Path string `json:"path"`
}

type composedURLParam struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type pathSegment struct {
	literal  string
	param    *composedURLParam
	optional bool
}

type Upstream struct {
	// PreserveHost, if false (the default), tells ORY Oathkeeper to set the upstream request's Host header to the
	// hostname of the API's upstream's URL. Setting this flag to true instructs ORY Oathkeeper not to do so.
	PreserveHost bool `json:"preserve_host"`

	// StripPath if set, replaces the provided path prefix when forwarding the requested URL to the upstream URL.
	StripPath string `json:"strip_path"`

	// URL is the URL the request will be proxied to.
	URL string `json:"url"`
}

var _ json.Unmarshaler = new(Rule)

func (r *Rule) UnmarshalJSON(raw []byte) error {
	var rr struct {
		ID             string         `json:"id"`
		Version        string         `json:"version"`
		Description    string         `json:"description"`
		Authenticators []Handler      `json:"authenticators"`
		Authorizer     Handler        `json:"authorizer"`
		Mutators       []Handler      `json:"mutators"`
		Errors         []ErrorHandler `json:"errors"`
		Upstream       Upstream       `json:"upstream"`

		RawMatch json.RawMessage `json:"match"`
		Match    URLProvider
	}

	transformed, err := migrateRuleJSON(raw)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := json.Unmarshal(transformed, &rr); err != nil {
		return errors.WithStack(err)
	}
	if rr.RawMatch != nil {
		if err := unmarshalMatch(rr.RawMatch, &rr.Match); err != nil {
			return errors.WithStack(err)
		}
	}

	// copy all fields
	r.ID = rr.ID
	r.Version = rr.Version
	r.Description = rr.Description
	r.Match = rr.Match
	r.Authenticators = rr.Authenticators
	r.Authorizer = rr.Authorizer
	r.Mutators = rr.Mutators
	r.Errors = rr.Errors
	r.Upstream = rr.Upstream
	if m, ok := rr.Match.(*Match); ok && m.isComposed {
		r.requiresComposed = true
		var rawMatch struct {
			URL json.RawMessage `json:"url"`
		}
		if err := json.Unmarshal(rr.RawMatch, &rawMatch); err != nil {
			return errors.WithStack(err)
		}
		var cu composedURL
		if err := json.Unmarshal(rawMatch.URL, &cu); err != nil {
			return errors.WithStack(err)
		}
		compiled, err := compileComposedURL(cu)
		if err != nil {
			return err
		}
		r.composedRegexpPattern = compiled.RegexpPattern
		r.composedGlobPattern = compiled.GlobPattern
		var compact bytes.Buffer
		if err := json.Compact(&compact, rawMatch.URL); err != nil {
			return errors.WithStack(err)
		}
		r.composedRawURL = append(json.RawMessage(nil), compact.Bytes()...)
	}

	return nil
}

func (r Rule) MarshalJSON() ([]byte, error) {
	type ruleAlias struct {
		ID             string         `json:"id"`
		Version        string         `json:"version"`
		Description    string         `json:"description"`
		Match          any            `json:"match"`
		Authenticators []Handler      `json:"authenticators"`
		Authorizer     Handler        `json:"authorizer"`
		Mutators       []Handler      `json:"mutators"`
		Errors         []ErrorHandler `json:"errors"`
		Upstream       Upstream       `json:"upstream"`
	}

	out := ruleAlias{
		ID:             r.ID,
		Version:        r.Version,
		Description:    r.Description,
		Authenticators: r.Authenticators,
		Authorizer:     r.Authorizer,
		Mutators:       r.Mutators,
		Errors:         r.Errors,
		Upstream:       r.Upstream,
	}

	if m, ok := r.Match.(*Match); ok && m.isComposed && len(r.composedRawURL) > 0 {
		out.Match = struct {
			Methods []string        `json:"methods"`
			URL     json.RawMessage `json:"url"`
		}{
			Methods: m.Methods,
			URL:     r.composedRawURL,
		}
	} else {
		out.Match = r.Match
	}

	return json.Marshal(out)
}

// unmarshalMatch does polymorphic decoding of the match based on keys.
func unmarshalMatch(raw json.RawMessage, v *URLProvider) error {
	if gjson.Get(string(raw), "full_method").Exists() {
		// full_method --> grpc matching rule
		*v = new(MatchGRPC)
		return json.Unmarshal(raw, *v)
	}

	var probe struct {
		Methods []string        `json:"methods"`
		URL     json.RawMessage `json:"url"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return errors.WithStack(err)
	}

	if len(probe.URL) == 0 {
		*v = &Match{Methods: probe.Methods}
		return nil
	}

	if probe.URL[0] == '"' {
		*v = new(Match)
		return json.Unmarshal(raw, *v)
	}

	if probe.URL[0] != '{' {
		return errors.New(`"match.url" must be either a string or an object`)
	}

	var cu composedURL
	if err := json.Unmarshal(probe.URL, &cu); err != nil {
		return errors.WithStack(err)
	}

	compiled, err := compileComposedURL(cu)
	if err != nil {
		return err
	}

	*v = &Match{Methods: probe.Methods, URL: compiled.RegexpPattern, isComposed: true}
	return nil
}

// GetID returns the rule's ID.
func (r *Rule) GetID() string {
	return r.ID
}

// IsMatching checks whether the provided url and method match the rule.
// An error will be returned if a regexp matching strategy is selected and regexp timeout occurs.
func (r *Rule) IsMatching(strategy configuration.MatchingStrategy, method string, u *url.URL, protocol Protocol) (bool, error) {
	if r.Match == nil {
		return false, errors.New("no Match configured (was nil)")
	}
	if !stringInSlice(method, r.Match.GetMethods()) {
		return false, nil
	}
	if err := ensureMatchingEngine(r, strategy); err != nil {
		return false, err
	}
	if r.Match.Protocol() != protocol {
		return false, nil
	}

	matchAgainst := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
	if strategy == configuration.Glob && r.requiresComposed {
		// Composed match.url is intentionally regexp-only to avoid strategy ambiguity.
		return false, nil
	}
	return r.matchingEngine.IsMatching(r.Match.GetURL(), matchAgainst)
}

// ReplaceAllString searches the input string and replaces each match (with the rule's pattern)
// found with the replacement text.
func (r *Rule) ReplaceAllString(strategy configuration.MatchingStrategy, input, replacement string) (string, error) {
	if err := ensureMatchingEngine(r, strategy); err != nil {
		return "", err
	}

	return r.matchingEngine.ReplaceAllString(r.Match.GetURL(), input, replacement)
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if strings.EqualFold(a, b) {
			return true
		}
	}
	return false
}

func ensureMatchingEngine(rule *Rule, strategy configuration.MatchingStrategy) error {
	if rule.matchingEngine != nil {
		return nil
	}
	switch strategy {
	case configuration.Glob:
		rule.matchingEngine = new(globMatchingEngine)
		return nil
	case "", configuration.Regexp:
		rule.matchingEngine = new(regexpMatchingEngine)
		return nil
	}

	return errors.Wrap(ErrUnknownMatchingStrategy, string(strategy))
}

// ExtractRegexGroups returns the values matching the rule pattern
func (r *Rule) ExtractRegexGroups(strategy configuration.MatchingStrategy, u *url.URL) ([]string, map[string]string, error) {
	var (
		err         error
		groups      []string
		namedGroups map[string]string
	)
	if err = ensureMatchingEngine(r, strategy); err != nil {
		return nil, nil, err
	}

	if r.Match == nil {
		return []string{}, map[string]string{}, nil
	}

	matchAgainst := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
	if strategy == configuration.Glob && r.requiresComposed {
		return []string{}, map[string]string{}, nil
	}

	if groups, err = r.matchingEngine.FindStringSubmatch(r.Match.GetURL(), matchAgainst); err != nil {
		return nil, nil, err
	}

	if namedGroups, err = r.matchingEngine.FindNamedStringSubmatch(r.Match.GetURL(), matchAgainst); err != nil {
		if groups != nil {
			return groups, nil, err
		}
		return nil, nil, err
	}

	return groups, namedGroups, nil
}

type composedURLCompiled struct {
	RegexpPattern string
	GlobPattern   string
}

func compileComposedURL(c composedURL) (*composedURLCompiled, error) {
	if strings.TrimSpace(c.Base) == "" {
		return nil, errors.New(`"match.url.base" must not be empty`)
	}
	if len(c.Paths) == 0 {
		return nil, errors.New(`"match.url.paths" must not be empty`)
	}

	paramDefs := make(map[string]composedURLParam, len(c.PathParams))
	paramUsage := make(map[string]bool, len(c.PathParams))
	for _, p := range c.PathParams {
		if p.Name == "" {
			return nil, errors.New(`"match.url.path_params[].name" must not be empty`)
		}
		if _, exists := paramDefs[p.Name]; exists {
			return nil, errors.Errorf(`duplicate "match.url.path_params" name: %s`, p.Name)
		}
		if p.Type != "regex" {
			return nil, errors.Errorf(`unsupported "match.url.path_params[%s].type": %s`, p.Name, p.Type)
		}
		if p.Value == "" {
			return nil, errors.Errorf(`"match.url.path_params[%s].value" must not be empty`, p.Name)
		}
		if _, err := regexp.Compile(p.Value); err != nil {
			return nil, errors.Errorf(`invalid regex for "match.url.path_params[%s]": %s`, p.Name, err)
		}
		paramDefs[p.Name] = p
	}

	regexAlts := make([]string, 0)
	regexAltSet := make(map[string]struct{})
	globAlts := make([]string, 0)
	globAltSet := make(map[string]struct{})
	parsedBranchTemplates := make([][]pathSegment, 0)
	for i, p := range c.Paths {
		if p.Prefix != "" && !strings.HasPrefix(p.Prefix, "/") {
			return nil, errors.Errorf(`"match.url.paths[%d].prefix" must be empty or start with "/"`, i)
		}
		if len(p.Branches) == 0 {
			return nil, errors.Errorf(`"match.url.paths[%d].branches" must not be empty`, i)
		}
		for j, b := range p.Branches {
			if !strings.HasPrefix(b.Path, "/") {
				return nil, errors.Errorf(`"match.url.paths[%d].branches[%d].path" must start with "/"`, i, j)
			}
			fullPath := joinPathPrefixAndBranch(p.Prefix, b.Path)
			segments, used, err := parsePathTemplate(fullPath, paramDefs)
			if err != nil {
				return nil, errors.Wrapf(err, "invalid composed path at paths[%d].branches[%d]", i, j)
			}
			for name := range used {
				paramUsage[name] = true
			}
			compiledRegexPath := compileSegmentsToRegex(segments)
			if _, dup := regexAltSet[compiledRegexPath]; dup {
				return nil, errors.Errorf(`duplicate composed URL branch expansion detected: %s`, fullPath)
			}
			regexAltSet[compiledRegexPath] = struct{}{}
			regexAlts = append(regexAlts, compiledRegexPath)

			for _, variant := range expandOptionalSegments(segments) {
				globPath := compileSegmentsToGlob(variant)
				if _, dup := globAltSet[globPath]; !dup {
					globAltSet[globPath] = struct{}{}
					globAlts = append(globAlts, globPath)
				}
			}
			parsedBranchTemplates = append(parsedBranchTemplates, segments)
		}
	}

	if err := detectComposedBranchOverlaps(parsedBranchTemplates); err != nil {
		return nil, err
	}

	for name := range paramDefs {
		if !paramUsage[name] {
			return nil, errors.Errorf(`"match.url.path_params[%s]" is declared but never used`, name)
		}
	}

	sort.Strings(regexAlts)
	sort.Strings(globAlts)
	return &composedURLCompiled{
		RegexpPattern: fmt.Sprintf(`%s<<(?:%s)$>>`, c.Base, strings.Join(regexAlts, "|")),
		GlobPattern:   fmt.Sprintf(`%s<{%s}>`, c.Base, strings.Join(globAlts, ",")),
	}, nil
}

func joinPathPrefixAndBranch(prefix, branch string) string {
	if strings.HasSuffix(prefix, "/") {
		prefix = strings.TrimSuffix(prefix, "/")
	}
	return prefix + branch
}

func parsePathTemplate(path string, paramDefs map[string]composedURLParam) ([]pathSegment, map[string]struct{}, error) {
	segments := strings.Split(path, "/")
	if len(segments) == 0 || segments[0] != "" {
		return nil, nil, errors.New(`path must be absolute`)
	}

	used := make(map[string]struct{})
	result := make([]pathSegment, 0, len(segments)-1)
	for _, segment := range segments[1:] {
		if segment == "" {
			return nil, nil, errors.New(`empty path segments are not allowed`)
		}
		if strings.HasPrefix(segment, ":") {
			optional := strings.HasSuffix(segment, "?")
			name := strings.TrimPrefix(strings.TrimSuffix(segment, "?"), ":")
			if name == "" {
				return nil, nil, errors.New(`parameter name must not be empty`)
			}
			if strings.Contains(name, "?") {
				return nil, nil, errors.Errorf(`invalid optional parameter syntax in segment %q`, segment)
			}
			def, ok := paramDefs[name]
			if !ok {
				return nil, nil, errors.Errorf(`undefined path parameter: %s`, name)
			}
			if _, exists := used[name]; exists {
				return nil, nil, errors.Errorf(`path parameter %q is used more than once in the same branch`, name)
			}
			used[name] = struct{}{}
			d := def
			result = append(result, pathSegment{param: &d, optional: optional})
			continue
		}

		result = append(result, pathSegment{literal: segment})
	}

	return result, used, nil
}

func compileSegmentsToRegex(segments []pathSegment) string {
	var b strings.Builder
	for _, seg := range segments {
		if seg.param == nil {
			b.WriteString("/")
			b.WriteString(compileLiteralSegmentToRegex(seg.literal))
			continue
		}

		if seg.optional {
			b.WriteString(fmt.Sprintf(`(?:/(?<%s>%s))?`, seg.param.Name, seg.param.Value))
		} else {
			b.WriteString(fmt.Sprintf(`/(?<%s>%s)`, seg.param.Name, seg.param.Value))
		}
	}
	return b.String()
}

func compileSegmentsToGlob(segments []pathSegment) string {
	var b strings.Builder
	for _, seg := range segments {
		if seg.param != nil {
			b.WriteString("/*")
			continue
		}
		b.WriteString("/")
		b.WriteString(compileLiteralSegmentToGlob(seg.literal))
	}
	return b.String()
}

func detectComposedBranchOverlaps(templates [][]pathSegment) error {
	expanded := make([][][]pathSegment, len(templates))
	for i, tpl := range templates {
		expanded[i] = expandOptionalSegments(tpl)
	}

	for i := 0; i < len(expanded); i++ {
		for j := i + 1; j < len(expanded); j++ {
			if variantsOverlap(expanded[i], expanded[j]) {
				return errors.Errorf("composed URL branches overlap and may cause ambiguous rule matching between branch indexes %d and %d", i, j)
			}
		}
	}
	return nil
}

func expandOptionalSegments(segments []pathSegment) [][]pathSegment {
	out := [][]pathSegment{{}}
	for _, seg := range segments {
		next := make([][]pathSegment, 0, len(out)*2)
		if seg.param != nil && seg.optional {
			for _, cur := range out {
				withSeg := append(append([]pathSegment{}, cur...), pathSegment{param: seg.param, optional: false})
				withoutSeg := append([]pathSegment{}, cur...)
				next = append(next, withSeg, withoutSeg)
			}
		} else {
			for _, cur := range out {
				next = append(next, append(append([]pathSegment{}, cur...), seg))
			}
		}
		out = next
	}
	return out
}

func variantsOverlap(left, right [][]pathSegment) bool {
	for _, l := range left {
		for _, r := range right {
			if len(l) != len(r) {
				continue
			}
			maybe := true
			for i := range l {
				if !segmentsCompatible(l[i], r[i]) {
					maybe = false
					break
				}
			}
			if maybe {
				return true
			}
		}
	}
	return false
}

func segmentsCompatible(a, b pathSegment) bool {
	if a.param == nil && b.param == nil {
		aGlob := hasGlobWildcards(a.literal)
		bGlob := hasGlobWildcards(b.literal)
		if !aGlob && !bGlob {
			return a.literal == b.literal
		}
		if aGlob && bGlob {
			// Conservative: two glob patterns in same segment may overlap.
			return true
		}
		if aGlob {
			return globLiteralMatchesStatic(a.literal, b.literal)
		}
		return globLiteralMatchesStatic(b.literal, a.literal)
	}
	if a.param != nil && b.param != nil {
		// Conservative: two regex params at same segment are considered overlapping.
		return true
	}
	if a.param != nil {
		if hasGlobWildcards(b.literal) {
			// Conservative: glob-literal may generate values matching regex param.
			return true
		}
		return staticMatchesRegex(b.literal, a.param.Value)
	}
	if hasGlobWildcards(a.literal) {
		// Conservative: glob-literal may generate values matching regex param.
		return true
	}
	return staticMatchesRegex(a.literal, b.param.Value)
}

func staticMatchesRegex(s, pattern string) bool {
	re, err := regexp.Compile("^" + pattern + "$")
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

func hasGlobWildcards(s string) bool {
	return strings.ContainsAny(s, "*?")
}

func compileLiteralSegmentToRegex(segment string) string {
	if !hasGlobWildcards(segment) {
		return regexp.QuoteMeta(segment)
	}

	var b strings.Builder
	for _, r := range segment {
		switch r {
		case '*':
			b.WriteString(`[^/]*`)
		case '?':
			b.WriteString(`[^/]`)
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return b.String()
}

func compileLiteralSegmentToGlob(segment string) string {
	var b strings.Builder
	for _, r := range segment {
		switch r {
		case '*', '?':
			b.WriteRune(r)
		default:
			b.WriteString(glob.QuoteMeta(string(r)))
		}
	}
	return b.String()
}

func globLiteralMatchesStatic(globPattern, candidate string) bool {
	re, err := regexp.Compile("^" + compileLiteralSegmentToRegex(globPattern) + "$")
	if err != nil {
		return false
	}
	return re.MatchString(candidate)
}
