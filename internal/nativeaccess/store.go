package nativeaccess

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const hashPrefix = "sha256:"

type Grant struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Group    string `json:"group,omitempty"`
	// UpstreamPrefix and the compatibility fields are retained only so an
	// existing state file can be read during migration. Native-access mode no
	// longer accepts client-visible provider prefixes or model aliases.
	UpstreamPrefix   string   `json:"upstream_prefix,omitempty"`
	AcceptedPrefixes []string `json:"accepted_prefixes,omitempty"`
	AcceptedModels   []string `json:"accepted_models,omitempty"`
}

type Policy struct {
	PrincipalID  string  `json:"principal_id,omitempty"`
	KeyHash      string  `json:"key_hash"`
	Enabled      bool    `json:"enabled"`
	Grants       []Grant `json:"grants"`
	RPM          int     `json:"rpm,omitempty"`
	DailyCalls   int64   `json:"daily_calls,omitempty"`
	WeeklyCalls  int64   `json:"weekly_calls,omitempty"`
	DailyTokens  int64   `json:"daily_tokens,omitempty"`
	WeeklyTokens int64   `json:"weekly_tokens,omitempty"`
}

type Credential struct {
	KeyHash     string     `json:"key_hash"`
	PrincipalID string     `json:"principal_id"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	RetiredAt   *time.Time `json:"retired_at,omitempty"`
}

type window struct {
	Start  time.Time `json:"start"`
	Calls  int64     `json:"calls"`
	Tokens int64     `json:"tokens"`
}

type usage struct {
	Daily  window `json:"daily"`
	Weekly window `json:"weekly"`
}

type state struct {
	Version     int               `json:"version"`
	Policies    []Policy          `json:"policies"`
	Usage       map[string]*usage `json:"usage,omitempty"`
	Principals  []Policy          `json:"principals,omitempty"`
	Credentials []Credential      `json:"credentials,omitempty"`
}

type Identity struct {
	PrincipalID      string `json:"principal_id,omitempty"`
	KeyHash          string `json:"key_hash"`
	CredentialHash   string `json:"credential_hash"`
	CallerScope      string `json:"caller_scope"`
	Preview          string `json:"key_preview"`
	Managed          bool   `json:"managed"`
	Active           bool   `json:"active"`
	CredentialStatus string `json:"credential_status"`
}

type Decision struct {
	Known       bool
	Allowed     bool
	Principal   string
	KeyHash     string
	Provider    string
	Model       string
	TargetModel string
	Group       string
	Reason      string
}

type grantMatch struct {
	grant          Grant
	canonicalModel string
	score          int
}

type nativeConfig struct {
	APIKeys []string `yaml:"api-keys"`
}

type Store struct {
	mu                sync.Mutex
	keysFile          string
	stateFile         string
	keysModTime       int64
	keysSize          int64
	stateModTime      int64
	stateSize         int64
	activeByHash      map[string]string
	scopeByHash       map[string]string
	policiesByHash    map[string]Policy
	credentialsByHash map[string]Credential
	usageByHash       map[string]*usage
	rpm               map[string][]time.Time
	now               func() time.Time
	dirty             bool
	lastFlush         time.Time
	flushScheduled    bool
}

func New(keysFile, stateFile string) (*Store, error) {
	keysFile, err := absolutePath(keysFile)
	if err != nil {
		return nil, err
	}
	stateFile, err = absolutePath(stateFile)
	if err != nil {
		return nil, err
	}
	s := &Store{
		keysFile:          keysFile,
		stateFile:         stateFile,
		activeByHash:      make(map[string]string),
		scopeByHash:       make(map[string]string),
		policiesByHash:    make(map[string]Policy),
		credentialsByHash: make(map[string]Credential),
		usageByHash:       make(map[string]*usage),
		rpm:               make(map[string][]time.Time),
		now:               time.Now,
	}
	if err := s.loadStateLocked(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := s.refreshKeysLocked(true); err != nil {
		return nil, err
	}
	return s, nil
}

func absolutePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("path is required")
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	return filepath.Abs(path)
}

func HashKey(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return hashPrefix + hex.EncodeToString(sum[:])
}

func CallerScopeKey(key string) string {
	sum := sha256.Sum256([]byte("cli-proxy-api:caller-scope:v1\x00" + strings.TrimSpace(key)))
	return hex.EncodeToString(sum[:])
}

func PreviewKey(key string) string {
	key = strings.TrimSpace(key)
	if len(key) <= 12 {
		return key
	}
	return key[:7] + "..." + key[len(key)-5:]
}

func newPrincipalID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	return fmt.Sprintf("principal_%08x-%04x-%04x-%04x-%012x",
		raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}

func legacyPrincipalID(keyHash string) string {
	sum := sha256.Sum256([]byte("cpa-key-policy:principal:v1\x00" + keyHash))
	raw := sum[:16]
	raw[6] = (raw[6] & 0x0f) | 0x50
	raw[8] = (raw[8] & 0x3f) | 0x80
	return fmt.Sprintf("principal_%08x-%04x-%04x-%04x-%012x",
		raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
}

func normalizePolicy(input Policy) (Policy, error) {
	input.PrincipalID = strings.TrimSpace(input.PrincipalID)
	input.KeyHash = strings.ToLower(strings.TrimSpace(input.KeyHash))
	if !strings.HasPrefix(input.KeyHash, hashPrefix) || len(input.KeyHash) != len(hashPrefix)+64 {
		return Policy{}, errors.New("key_hash must be a sha256 hash")
	}
	return normalizePolicyRules(input)
}

func normalizePrincipalPolicy(input Policy) (Policy, error) {
	input.PrincipalID = strings.TrimSpace(input.PrincipalID)
	if input.PrincipalID == "" {
		return Policy{}, errors.New("principal_id is required")
	}
	input.KeyHash = ""
	return normalizePolicyRules(input)
}

func normalizePolicyRules(input Policy) (Policy, error) {
	if input.RPM < 0 || input.DailyCalls < 0 || input.WeeklyCalls < 0 ||
		input.DailyTokens < 0 || input.WeeklyTokens < 0 {
		return Policy{}, errors.New("quotas cannot be negative")
	}
	seen := make(map[string]struct{}, len(input.Grants))
	grants := make([]Grant, 0, len(input.Grants))
	for _, grant := range input.Grants {
		grant.Provider = strings.ToLower(strings.TrimSpace(grant.Provider))
		grant.Model = strings.TrimSpace(grant.Model)
		grant.Group = strings.TrimSpace(grant.Group)
		grant.UpstreamPrefix = strings.ToLower(strings.Trim(strings.TrimSpace(grant.UpstreamPrefix), "/"))
		if strings.Contains(grant.UpstreamPrefix, "/") {
			return Policy{}, errors.New("upstream_prefix must be one CPA native prefix without '/'")
		}
		prefixes := make([]string, 0, len(grant.AcceptedPrefixes))
		prefixSeen := make(map[string]struct{}, len(grant.AcceptedPrefixes))
		for _, prefix := range grant.AcceptedPrefixes {
			prefix = strings.TrimSpace(prefix)
			if prefix == "" || strings.Contains(prefix, "/") {
				return Policy{}, errors.New("accepted_prefixes must be non-empty client prefixes without '/'")
			}
			lower := strings.ToLower(prefix)
			if _, exists := prefixSeen[lower]; exists {
				continue
			}
			prefixSeen[lower] = struct{}{}
			prefixes = append(prefixes, prefix)
		}
		sort.Strings(prefixes)
		grant.AcceptedPrefixes = prefixes
		models := make([]string, 0, len(grant.AcceptedModels))
		modelSeen := make(map[string]struct{}, len(grant.AcceptedModels))
		for _, acceptedModel := range grant.AcceptedModels {
			acceptedModel = strings.TrimSpace(acceptedModel)
			if acceptedModel == "" || strings.ContainsAny(acceptedModel, "*?") {
				return Policy{}, errors.New("accepted_models must contain exact non-empty model names")
			}
			lower := strings.ToLower(acceptedModel)
			if _, exists := modelSeen[lower]; exists {
				continue
			}
			modelSeen[lower] = struct{}{}
			models = append(models, acceptedModel)
		}
		sort.Strings(models)
		grant.AcceptedModels = models
		if len(grant.AcceptedModels) > 0 && strings.ContainsAny(grant.Model, "*?") {
			return Policy{}, errors.New("accepted_models require an exact canonical model")
		}
		if grant.Provider == "" || grant.Model == "" {
			return Policy{}, errors.New("each grant requires provider and model")
		}
		if grant.Provider == "*" && (grant.Group != "" || grant.UpstreamPrefix != "") {
			return Policy{}, errors.New("group and upstream_prefix require a concrete provider")
		}
		// Legacy dash aliases are no longer client-visible. Keep only CPA's
		// native upstream prefix so an explicitly authorized "prefix/model"
		// request can select the same provider/group grant.
		grant.AcceptedPrefixes = nil
		grant.AcceptedModels = nil
		id := grant.Provider + "\x00" + strings.ToLower(grant.Model) + "\x00" +
			strings.ToLower(grant.Group) + "\x00" + strings.ToLower(grant.UpstreamPrefix) +
			"\x00" + strings.ToLower(strings.Join(grant.AcceptedPrefixes, "\x01")) +
			"\x00" + strings.ToLower(strings.Join(grant.AcceptedModels, "\x01"))
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		grants = append(grants, grant)
	}
	sort.Slice(grants, func(i, j int) bool {
		if grants[i].Provider == grants[j].Provider {
			return grants[i].Model < grants[j].Model
		}
		return grants[i].Provider < grants[j].Provider
	})
	input.Grants = grants
	return input, nil
}

func wildcardMatch(pattern, value string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	value = strings.ToLower(strings.TrimSpace(value))
	if pattern == "*" {
		return true
	}
	expression := "^" + strings.ReplaceAll(
		strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*"),
		`\?`,
		".",
	) + "$"
	matched, err := regexp.MatchString(expression, value)
	return err == nil && matched
}

func matchGrant(grant Grant, requestedModel string) (canonicalModel string, score int, ok bool) {
	requestedModel = strings.TrimSpace(requestedModel)
	canonicalModel = requestedModel
	if !wildcardMatch(grant.Model, canonicalModel) {
		return "", -1, false
	}
	score = modelPatternSpecificity(grant.Model)
	if grant.Provider != "*" {
		score += 2
	}
	score++
	return canonicalModel, score, true
}

func modelPatternSpecificity(pattern string) int {
	pattern = strings.TrimSpace(pattern)
	literalLength := len(strings.NewReplacer("*", "", "?", "").Replace(pattern))
	if !strings.ContainsAny(pattern, "*?") {
		return 10_000 + literalLength*10
	}
	return literalLength * 10
}

func grantScore(grant Grant, model string) int {
	_, score, ok := matchGrant(grant, model)
	if !ok {
		return -1
	}
	return score
}

func matchingNativePrefixGrants(policy Policy, requestedModel string) (string, []grantMatch, bool) {
	requestedModel = strings.TrimSpace(requestedModel)
	prefix, model, slash := strings.Cut(requestedModel, "/")
	prefix = strings.Trim(prefix, "/ ")
	model = strings.TrimSpace(model)
	if !slash || prefix == "" || model == "" {
		return "", nil, false
	}
	matches := make([]grantMatch, 0, len(policy.Grants))
	bestScore := -1
	for _, grant := range policy.Grants {
		if grant.UpstreamPrefix == "" || !strings.EqualFold(grant.UpstreamPrefix, prefix) {
			continue
		}
		canonicalModel, score, matched := matchGrant(grant, model)
		if !matched {
			continue
		}
		if score > bestScore {
			matches = matches[:0]
			bestScore = score
		}
		if score == bestScore {
			matches = append(matches, grantMatch{
				grant:          grant,
				canonicalModel: canonicalModel,
				score:          score,
			})
		}
	}
	return model, matches, len(matches) > 0
}

func hasLegacyClientUpstreamSelector(policy Policy, requestedModel string) bool {
	requestedModel = strings.TrimSpace(requestedModel)
	for _, grant := range policy.Grants {
		for _, acceptedModel := range grant.AcceptedModels {
			if strings.EqualFold(strings.TrimSpace(acceptedModel), requestedModel) {
				return true
			}
		}
		for _, acceptedPrefix := range grant.AcceptedPrefixes {
			if acceptedPrefix != "" && len(requestedModel) > len(acceptedPrefix) &&
				strings.EqualFold(requestedModel[:len(acceptedPrefix)], acceptedPrefix) {
				return true
			}
		}
	}
	return false
}

func matchingGrants(policy Policy, requestedModel string) []grantMatch {
	matches := make([]grantMatch, 0, len(policy.Grants))
	bestScore := -1
	for _, grant := range policy.Grants {
		canonicalModel, score, matched := matchGrant(grant, requestedModel)
		if !matched {
			continue
		}
		if score > bestScore {
			matches = matches[:0]
			bestScore = score
		}
		if score == bestScore {
			matches = append(matches, grantMatch{
				grant:          grant,
				canonicalModel: canonicalModel,
				score:          score,
			})
		}
	}
	return matches
}

// routeDecision authorizes canonical model names and CPA's native
// "prefix/model" syntax. Native prefixes are accepted only when the same grant
// authorizes both the prefix and canonical model; legacy dash aliases remain
// forbidden. scheduler.pick applies the matching grant set to auth candidates.
func routeDecision(policy Policy, requestedModel string) Decision {
	requestedModel = strings.TrimSpace(requestedModel)
	if canonicalModel, matches, ok := matchingNativePrefixGrants(policy, requestedModel); ok {
		return Decision{
			Allowed:     true,
			Provider:    matches[0].grant.Provider,
			Model:       requestedModel,
			TargetModel: canonicalModel,
			Group:       matches[0].grant.Group,
			Reason:      "allowed_native_upstream_prefix",
		}
	}
	if hasLegacyClientUpstreamSelector(policy, requestedModel) {
		return Decision{Model: requestedModel, Reason: "client_upstream_selector_forbidden"}
	}
	matches := matchingGrants(policy, requestedModel)
	if len(matches) == 0 {
		return Decision{Model: requestedModel, Reason: "model_not_allowed"}
	}
	return Decision{
		Allowed:     true,
		Model:       matches[0].canonicalModel,
		TargetModel: matches[0].canonicalModel,
		Reason:      "allowed_server_side_upstream_policy",
	}
}

func (s *Store) refreshKeysLocked(force bool) error {
	info, err := os.Stat(s.keysFile)
	if err != nil {
		return fmt.Errorf("read native CPA keys: %w", err)
	}
	if !force && s.keysModTime == info.ModTime().UnixNano() && s.keysSize == info.Size() {
		return nil
	}
	raw, err := os.ReadFile(s.keysFile)
	if err != nil {
		return fmt.Errorf("read native CPA keys: %w", err)
	}
	var cfg nativeConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parse native CPA keys: %w", err)
	}
	next := make(map[string]string, len(cfg.APIKeys))
	nextScopes := make(map[string]string, len(cfg.APIKeys))
	for _, key := range cfg.APIKeys {
		key = strings.TrimSpace(key)
		if key != "" {
			hash := HashKey(key)
			next[hash] = PreviewKey(key)
			nextScopes[hash] = CallerScopeKey(key)
		}
	}
	s.activeByHash = next
	s.scopeByHash = nextScopes
	s.keysModTime = info.ModTime().UnixNano()
	s.keysSize = info.Size()
	return nil
}

func (s *Store) refreshKeys() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshKeysLocked(false)
}

func (s *Store) loadStateLocked() error {
	raw, err := os.ReadFile(s.stateFile)
	if err != nil {
		return err
	}
	var data state
	if err := json.Unmarshal(raw, &data); err != nil {
		return fmt.Errorf("parse native policy state: %w", err)
	}
	inputPolicies := data.Principals
	legacy := len(inputPolicies) == 0 && len(data.Policies) > 0
	if legacy {
		inputPolicies = data.Policies
	}
	principals := make(map[string]Policy, len(inputPolicies))
	for _, input := range inputPolicies {
		if input.PrincipalID == "" {
			input.PrincipalID = legacyPrincipalID(input.KeyHash)
		}
		var policy Policy
		var err error
		if legacy {
			policy, err = normalizePolicy(input)
		} else {
			policy, err = normalizePrincipalPolicy(input)
		}
		if err != nil {
			return err
		}
		principals[policy.PrincipalID] = policy
	}
	credentials := make(map[string]Credential)
	if legacy {
		for _, policy := range principals {
			credentials[policy.KeyHash] = Credential{
				KeyHash: policy.KeyHash, PrincipalID: policy.PrincipalID,
				Status: "active", CreatedAt: time.Now().UTC(),
			}
		}
	} else {
		for _, credential := range data.Credentials {
			credential.KeyHash = strings.ToLower(strings.TrimSpace(credential.KeyHash))
			credential.PrincipalID = strings.TrimSpace(credential.PrincipalID)
			if _, ok := principals[credential.PrincipalID]; !ok {
				return fmt.Errorf("credential %s references unknown principal", credential.KeyHash)
			}
			credentials[credential.KeyHash] = credential
		}
	}
	nextPolicies := make(map[string]Policy, len(credentials))
	for hash, credential := range credentials {
		policy := principals[credential.PrincipalID]
		policy.KeyHash = hash
		nextPolicies[hash] = policy
	}
	s.policiesByHash = nextPolicies
	s.credentialsByHash = credentials
	if data.Usage != nil {
		if legacy {
			for hash, value := range data.Usage {
				if credential, ok := credentials[hash]; ok {
					mergeUsageMaps(s.usageByHash, map[string]*usage{credential.PrincipalID: value})
				}
			}
		} else {
			mergeUsageMaps(s.usageByHash, data.Usage)
		}
	}
	if info, statErr := os.Stat(s.stateFile); statErr == nil {
		s.stateModTime = info.ModTime().UnixNano()
		s.stateSize = info.Size()
	}
	return nil
}

func (s *Store) saveLocked() error {
	principalMap := make(map[string]Policy)
	for hash, policy := range s.policiesByHash {
		credential, ok := s.credentialsByHash[hash]
		if !ok {
			continue
		}
		policy.PrincipalID = credential.PrincipalID
		policy.KeyHash = ""
		principalMap[policy.PrincipalID] = policy
	}
	principals := make([]Policy, 0, len(principalMap))
	for _, policy := range principalMap {
		principals = append(principals, policy)
	}
	sort.Slice(principals, func(i, j int) bool { return principals[i].PrincipalID < principals[j].PrincipalID })
	credentials := make([]Credential, 0, len(s.credentialsByHash))
	for _, credential := range s.credentialsByHash {
		credentials = append(credentials, credential)
	}
	sort.Slice(credentials, func(i, j int) bool { return credentials[i].KeyHash < credentials[j].KeyHash })
	raw, err := json.MarshalIndent(state{Version: 2, Principals: principals, Credentials: credentials, Usage: s.usageByHash}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.stateFile), 0o750); err != nil {
		return err
	}
	temp := s.stateFile + ".tmp"
	file, err := os.OpenFile(temp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(temp, s.stateFile); err != nil {
		return err
	}
	if dir, err := os.Open(filepath.Dir(s.stateFile)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	if info, statErr := os.Stat(s.stateFile); statErr == nil {
		s.stateModTime = info.ModTime().UnixNano()
		s.stateSize = info.Size()
	}
	s.dirty = false
	s.lastFlush = s.now()
	return nil
}

func (s *Store) refreshStateLocked(force bool) error {
	info, err := os.Stat(s.stateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !force && s.stateModTime == info.ModTime().UnixNano() && s.stateSize == info.Size() {
		return nil
	}
	return s.loadStateLocked()
}

func mergeUsageMaps(current, incoming map[string]*usage) {
	for hash, source := range incoming {
		if source == nil {
			continue
		}
		target := current[hash]
		if target == nil {
			copyUsage := *source
			current[hash] = &copyUsage
			continue
		}
		mergeWindowMax(&target.Daily, source.Daily)
		mergeWindowMax(&target.Weekly, source.Weekly)
	}
}

func mergeWindowMax(target *window, source window) {
	if source.Start.After(target.Start) {
		*target = source
		return
	}
	if source.Start.Equal(target.Start) {
		if source.Calls > target.Calls {
			target.Calls = source.Calls
		}
		if source.Tokens > target.Tokens {
			target.Tokens = source.Tokens
		}
	}
}

func acquireFileLock(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	lockPath := path + ".lock"
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := os.Mkdir(lockPath, 0o700); err == nil {
			return func() { _ = os.Remove(lockPath) }, nil
		} else if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if info, err := os.Stat(lockPath); err == nil && time.Since(info.ModTime()) > time.Minute {
			_ = os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for state lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *Store) refreshState() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshStateLocked(false)
}

func (s *Store) Identities() ([]Identity, error) {
	if err := s.refreshKeys(); err != nil {
		return nil, err
	}
	if err := s.refreshState(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Identity, 0, len(s.activeByHash)+len(s.credentialsByHash))
	seenPrincipals := make(map[string]bool)
	for hash, preview := range s.activeByHash {
		policy, managed := s.policiesByHash[hash]
		principalID := policy.PrincipalID
		status := "unmanaged"
		if managed {
			status = "active"
			seenPrincipals[principalID] = true
		}
		out = append(out, Identity{
			PrincipalID:      principalID,
			KeyHash:          hash,
			CredentialHash:   hash,
			CallerScope:      s.scopeByHash[hash],
			Preview:          preview,
			Managed:          managed,
			Active:           true,
			CredentialStatus: status,
		})
	}
	for hash, credential := range s.credentialsByHash {
		if _, active := s.activeByHash[hash]; active || seenPrincipals[credential.PrincipalID] {
			continue
		}
		out = append(out, Identity{
			PrincipalID: credential.PrincipalID, KeyHash: hash, CredentialHash: hash,
			Managed: true, Active: false, CredentialStatus: "retired",
		})
		seenPrincipals[credential.PrincipalID] = true
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyHash < out[j].KeyHash })
	return out, nil
}

func (s *Store) Policies() []Policy {
	_ = s.refreshState()
	_ = s.refreshKeys()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Policy, 0, len(s.policiesByHash))
	hashes := make([]string, 0, len(s.policiesByHash))
	for hash := range s.policiesByHash {
		hashes = append(hashes, hash)
	}
	sort.Strings(hashes)
	seen := make(map[string]bool)
	for _, activeOnly := range []bool{true, false} {
		for _, hash := range hashes {
			policy := s.policiesByHash[hash]
			_, active := s.activeByHash[hash]
			if active != activeOnly || seen[policy.PrincipalID] {
				continue
			}
			policy.KeyHash = hash
			seen[policy.PrincipalID] = true
			out = append(out, policy)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PrincipalID < out[j].PrincipalID })
	return out
}

func (s *Store) Credentials(principalID string) []Credential {
	_ = s.refreshState()
	_ = s.refreshKeys()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Credential, 0)
	for hash, credential := range s.credentialsByHash {
		if principalID != "" && credential.PrincipalID != principalID {
			continue
		}
		if _, active := s.activeByHash[hash]; active {
			credential.Status = "active"
			credential.RetiredAt = nil
		} else {
			credential.Status = "retired"
		}
		out = append(out, credential)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (s *Store) Upsert(input Policy) error {
	_, err := s.Apply([]Policy{input}, false, false)
	return err
}

// Apply validates the complete input before changing state. It is the common
// write path for both the CPAMP UI and declarative/AI automation.
//
// replace=false merges the supplied policies into existing state.
// replace=true makes the supplied list the complete desired policy set.
// dryRun=true performs all validation but does not mutate or persist anything.
func (s *Store) Apply(inputs []Policy, replace, dryRun bool) ([]Policy, error) {
	normalized := make([]Policy, 0, len(inputs))
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		policy, err := normalizePolicy(input)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[policy.KeyHash]; duplicate {
			return nil, fmt.Errorf("duplicate policy for %s", policy.KeyHash)
		}
		seen[policy.KeyHash] = struct{}{}
		normalized = append(normalized, policy)
	}
	if err := s.refreshKeys(); err != nil {
		return nil, err
	}
	release, err := acquireFileLock(s.stateFile)
	if err != nil {
		return nil, err
	}
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshStateLocked(true); err != nil {
		return nil, err
	}
	for i := range normalized {
		policy := &normalized[i]
		if _, active := s.activeByHash[policy.KeyHash]; !active {
			return nil, fmt.Errorf("%s is not an active CPA api-key", policy.KeyHash)
		}
		if credential, exists := s.credentialsByHash[policy.KeyHash]; exists {
			if policy.PrincipalID != "" && policy.PrincipalID != credential.PrincipalID {
				return nil, fmt.Errorf("%s already belongs to %s", policy.KeyHash, credential.PrincipalID)
			}
			policy.PrincipalID = credential.PrincipalID
		} else if policy.PrincipalID == "" {
			principalID, idErr := newPrincipalID()
			if idErr != nil {
				return nil, idErr
			}
			policy.PrincipalID = principalID
		}
	}
	if dryRun {
		return normalized, nil
	}
	next := make(map[string]Policy, len(s.policiesByHash)+len(normalized))
	nextCredentials := make(map[string]Credential, len(s.credentialsByHash)+len(normalized))
	if !replace {
		for hash, policy := range s.policiesByHash {
			next[hash] = policy
		}
		for hash, credential := range s.credentialsByHash {
			nextCredentials[hash] = credential
		}
	}
	templates := make(map[string]Policy, len(normalized))
	for _, policy := range normalized {
		templates[policy.PrincipalID] = policy
		if _, exists := nextCredentials[policy.KeyHash]; !exists {
			nextCredentials[policy.KeyHash] = Credential{
				KeyHash: policy.KeyHash, PrincipalID: policy.PrincipalID,
				Status: "active", CreatedAt: s.now().UTC(),
			}
		}
	}
	// Policies belong to a stable principal, not to one credential version.
	// Preserve retired credential history for principals that remain in a full
	// replacement, and apply an edited policy to every credential version.
	for hash, credential := range s.credentialsByHash {
		template, updated := templates[credential.PrincipalID]
		if !updated {
			if replace {
				continue
			}
			continue
		}
		nextCredentials[hash] = credential
		template.KeyHash = hash
		next[hash] = template
	}
	for _, policy := range normalized {
		policy.KeyHash = strings.ToLower(strings.TrimSpace(policy.KeyHash))
		next[policy.KeyHash] = policy
	}
	previous := s.policiesByHash
	previousCredentials := s.credentialsByHash
	s.policiesByHash = next
	s.credentialsByHash = nextCredentials
	if err := s.saveLocked(); err != nil {
		s.policiesByHash = previous
		s.credentialsByHash = previousCredentials
		return nil, err
	}
	return normalized, nil
}

func (s *Store) Delete(hash string) error {
	hash = strings.ToLower(strings.TrimSpace(hash))
	release, err := acquireFileLock(s.stateFile)
	if err != nil {
		return err
	}
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshStateLocked(true); err != nil {
		return err
	}
	if credential, ok := s.credentialsByHash[hash]; ok {
		for credentialHash, item := range s.credentialsByHash {
			if item.PrincipalID == credential.PrincipalID {
				delete(s.credentialsByHash, credentialHash)
				delete(s.policiesByHash, credentialHash)
			}
		}
		delete(s.usageByHash, credential.PrincipalID)
		delete(s.rpm, credential.PrincipalID)
	}
	return s.saveLocked()
}

func (s *Store) ContinueRotation(principalID, newKeyHash string) error {
	principalID = strings.TrimSpace(principalID)
	newKeyHash = strings.ToLower(strings.TrimSpace(newKeyHash))
	if principalID == "" {
		return errors.New("principal_id is required")
	}
	if !strings.HasPrefix(newKeyHash, hashPrefix) || len(newKeyHash) != len(hashPrefix)+64 {
		return errors.New("new_key_hash must be a sha256 hash")
	}
	if err := s.refreshKeys(); err != nil {
		return err
	}
	release, err := acquireFileLock(s.stateFile)
	if err != nil {
		return err
	}
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshStateLocked(true); err != nil {
		return err
	}
	if _, active := s.activeByHash[newKeyHash]; !active {
		return errors.New("new credential is not an active CPA api-key")
	}
	if _, managed := s.credentialsByHash[newKeyHash]; managed {
		return errors.New("new credential is already managed")
	}
	var template Policy
	found := false
	hasRetired := false
	for hash, credential := range s.credentialsByHash {
		if credential.PrincipalID != principalID {
			continue
		}
		template = s.policiesByHash[hash]
		found = true
		if _, active := s.activeByHash[hash]; !active {
			hasRetired = true
		}
	}
	if !found {
		return errors.New("principal not found")
	}
	if !hasRetired {
		return errors.New("principal has no retired credential to continue")
	}
	previousPolicies := clonePolicyMap(s.policiesByHash)
	previousCredentials := cloneCredentialMap(s.credentialsByHash)
	now := s.now().UTC()
	for hash, credential := range s.credentialsByHash {
		if credential.PrincipalID != principalID {
			continue
		}
		if _, active := s.activeByHash[hash]; !active {
			credential.Status = "retired"
			if credential.RetiredAt == nil {
				credential.RetiredAt = &now
			}
			s.credentialsByHash[hash] = credential
		}
	}
	template.KeyHash = newKeyHash
	template.PrincipalID = principalID
	s.policiesByHash[newKeyHash] = template
	s.credentialsByHash[newKeyHash] = Credential{
		KeyHash: newKeyHash, PrincipalID: principalID, Status: "active", CreatedAt: now,
	}
	if err := s.saveLocked(); err != nil {
		s.policiesByHash = previousPolicies
		s.credentialsByHash = previousCredentials
		return err
	}
	return nil
}

func (s *Store) UndoRotation(principalID, newKeyHash string) error {
	principalID = strings.TrimSpace(principalID)
	newKeyHash = strings.ToLower(strings.TrimSpace(newKeyHash))
	if err := s.refreshKeys(); err != nil {
		return err
	}
	release, err := acquireFileLock(s.stateFile)
	if err != nil {
		return err
	}
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshStateLocked(true); err != nil {
		return err
	}
	credential, ok := s.credentialsByHash[newKeyHash]
	if !ok || credential.PrincipalID != principalID {
		return errors.New("rotation binding not found")
	}
	if _, active := s.activeByHash[newKeyHash]; !active {
		return errors.New("new credential is no longer active")
	}
	previousPolicies := clonePolicyMap(s.policiesByHash)
	previousCredentials := cloneCredentialMap(s.credentialsByHash)
	delete(s.credentialsByHash, newKeyHash)
	delete(s.policiesByHash, newKeyHash)
	if err := s.saveLocked(); err != nil {
		s.policiesByHash = previousPolicies
		s.credentialsByHash = previousCredentials
		return err
	}
	return nil
}

func clonePolicyMap(input map[string]Policy) map[string]Policy {
	out := make(map[string]Policy, len(input))
	for hash, policy := range input {
		policy.Grants = append([]Grant(nil), policy.Grants...)
		out[hash] = policy
	}
	return out
}

func cloneCredentialMap(input map[string]Credential) map[string]Credential {
	out := make(map[string]Credential, len(input))
	for hash, credential := range input {
		if credential.RetiredAt != nil {
			retiredAt := *credential.RetiredAt
			credential.RetiredAt = &retiredAt
		}
		out[hash] = credential
	}
	return out
}

func resetWindows(u *usage, now time.Time) {
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	if u.Daily.Start.IsZero() || u.Daily.Start.Before(day) {
		u.Daily = window{Start: day}
	}
	week := day.AddDate(0, 0, -6)
	if u.Weekly.Start.IsZero() || u.Weekly.Start.Before(week) {
		u.Weekly = window{Start: now}
	}
}

func (s *Store) Authenticate(rawKey, model string, modelsEndpoint bool) Decision {
	if err := s.refreshKeys(); err != nil {
		return Decision{Reason: "native_keys_unavailable"}
	}
	if err := s.refreshState(); err != nil {
		return Decision{Reason: "policy_state_unavailable"}
	}
	hash := HashKey(rawKey)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, active := s.activeByHash[hash]; !active {
		return Decision{Reason: "unknown_native_key"}
	}
	decision := Decision{
		Known:   true,
		KeyHash: hash,
		Model:   model,
	}
	policy, exists := s.policiesByHash[hash]
	if !exists {
		decision.Reason = "policy_missing"
		return decision
	}
	decision.Principal = policy.PrincipalID
	if !policy.Enabled {
		decision.Reason = "policy_disabled"
		return decision
	}
	if modelsEndpoint {
		decision.Allowed = true
		decision.Reason = "models_endpoint_allowed"
		return decision
	}
	route := routeDecision(policy, model)
	if !route.Allowed {
		decision.Model = route.Model
		decision.Reason = route.Reason
		return decision
	}
	decision.Provider = route.Provider
	decision.Model = route.Model
	decision.TargetModel = route.TargetModel
	decision.Group = route.Group
	now := s.now()
	u := s.usageByHash[policy.PrincipalID]
	if u == nil {
		u = &usage{}
		s.usageByHash[policy.PrincipalID] = u
	}
	resetWindows(u, now)
	if policy.DailyCalls > 0 && u.Daily.Calls >= policy.DailyCalls {
		decision.Reason = "daily_calls_exceeded"
		return decision
	}
	if policy.WeeklyCalls > 0 && u.Weekly.Calls >= policy.WeeklyCalls {
		decision.Reason = "weekly_calls_exceeded"
		return decision
	}
	if policy.DailyTokens > 0 && u.Daily.Tokens >= policy.DailyTokens {
		decision.Reason = "daily_tokens_exceeded"
		return decision
	}
	if policy.WeeklyTokens > 0 && u.Weekly.Tokens >= policy.WeeklyTokens {
		decision.Reason = "weekly_tokens_exceeded"
		return decision
	}
	if policy.RPM > 0 {
		cutoff := now.Add(-time.Minute)
		recent := s.rpm[policy.PrincipalID][:0]
		for _, at := range s.rpm[policy.PrincipalID] {
			if at.After(cutoff) {
				recent = append(recent, at)
			}
		}
		if len(recent) >= policy.RPM {
			s.rpm[policy.PrincipalID] = recent
			decision.Reason = "rpm_exceeded"
			return decision
		}
		s.rpm[policy.PrincipalID] = append(recent, now)
	}
	u.Daily.Calls++
	u.Weekly.Calls++
	s.dirty = true
	decision.Allowed = true
	decision.Reason = route.Reason
	return decision
}

// Route returns the canonical model for an already-authorized request.
// Upstream selection is performed later by scheduler.pick.
func (s *Store) Route(rawKey, model string) (Decision, bool) {
	if err := s.refreshKeys(); err != nil {
		return Decision{}, false
	}
	if err := s.refreshState(); err != nil {
		return Decision{}, false
	}
	hash := HashKey(rawKey)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, active := s.activeByHash[hash]; !active {
		return Decision{}, false
	}
	policy, exists := s.policiesByHash[hash]
	if !exists || !policy.Enabled {
		return Decision{}, false
	}
	decision := routeDecision(policy, model)
	decision.Known = true
	decision.Principal = policy.PrincipalID
	decision.KeyHash = hash
	return decision, decision.Allowed
}

// RouteProvider is retained for API compatibility with earlier V2 callers.
func (s *Store) RouteProvider(rawKey, model string) (string, bool) {
	decision, ok := s.Route(rawKey, model)
	return decision.Provider, ok
}

// SchedulerGrants returns the complete best-matching grant set for a key and
// canonical model. The caller uses the set to filter CPA auth candidates.
func (s *Store) SchedulerGrants(keyHash, model string) ([]Grant, bool) {
	if err := s.refreshKeys(); err != nil {
		return nil, false
	}
	if err := s.refreshState(); err != nil {
		return nil, false
	}
	keyHash = strings.ToLower(strings.TrimSpace(keyHash))
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, active := s.activeByHash[keyHash]; !active {
		return nil, false
	}
	policy, exists := s.policiesByHash[keyHash]
	if !exists || !policy.Enabled || hasLegacyClientUpstreamSelector(policy, model) {
		return nil, false
	}
	if _, matches, ok := matchingNativePrefixGrants(policy, model); ok {
		grants := make([]Grant, 0, len(matches))
		for _, match := range matches {
			grants = append(grants, match.grant)
		}
		return grants, true
	}
	matches := matchingGrants(policy, model)
	if len(matches) == 0 {
		return nil, false
	}
	grants := make([]Grant, 0, len(matches))
	for _, match := range matches {
		grants = append(grants, match.grant)
	}
	return grants, true
}

// ProviderMatchesCandidate compares a policy provider with the provider name
// exposed by CPA's scheduler. OpenAI-compatible providers may be represented
// either as their configured name or as "openai-compatible-<name>".
func ProviderMatchesCandidate(pattern, candidate string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	if wildcardMatch(pattern, candidate) {
		return true
	}
	const compatiblePrefix = "openai-compatible-"
	if strings.HasPrefix(candidate, compatiblePrefix) {
		return wildcardMatch(pattern, strings.TrimPrefix(candidate, compatiblePrefix))
	}
	if strings.HasPrefix(pattern, compatiblePrefix) {
		return wildcardMatch(strings.TrimPrefix(pattern, compatiblePrefix), candidate)
	}
	return false
}

// FilterModels returns only model entries matched by at least one grant for
// the active native key. Provider constraints are enforced at routing time;
// the OpenAI model catalog itself is keyed by model ID.
func (s *Store) FilterModels(rawKey string, models []map[string]any, modelProviders map[string][]string) ([]map[string]any, bool) {
	if err := s.refreshKeys(); err != nil {
		return nil, false
	}
	if err := s.refreshState(); err != nil {
		return nil, false
	}
	hash := HashKey(rawKey)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, active := s.activeByHash[hash]; !active {
		return nil, false
	}
	policy, exists := s.policiesByHash[hash]
	if !exists || !policy.Enabled {
		return []map[string]any{}, true
	}
	filtered := make([]map[string]any, 0, len(models))
	seen := make(map[string]struct{}, len(models))
	appendModel := func(source map[string]any, id string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		key := strings.ToLower(id)
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		clone := make(map[string]any, len(source))
		for field, value := range source {
			clone[field] = value
		}
		clone["id"] = id
		filtered = append(filtered, clone)
	}
	for _, model := range models {
		id, _ := model["id"].(string)
		for _, grant := range policy.Grants {
			if !providerMatches(grant.Provider, modelProviders[id]) {
				continue
			}
			canonicalID := id
			if grant.UpstreamPrefix != "" {
				nativePrefix := grant.UpstreamPrefix + "/"
				if len(id) <= len(nativePrefix) || !strings.EqualFold(id[:len(nativePrefix)], nativePrefix) {
					continue
				}
				canonicalID = id[len(nativePrefix):]
			}
			if !wildcardMatch(grant.Model, canonicalID) {
				continue
			}
			appendModel(model, canonicalID)
		}
	}
	return filtered, true
}

func providerMatches(pattern string, providers []string) bool {
	if strings.TrimSpace(pattern) == "*" {
		return true
	}
	for _, provider := range providers {
		if wildcardMatch(pattern, provider) {
			return true
		}
	}
	return false
}

func (s *Store) RecordUsage(rawKey string, tokens int64) {
	if strings.TrimSpace(rawKey) == "" || tokens <= 0 {
		return
	}
	hash := HashKey(rawKey)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, active := s.activeByHash[hash]; !active {
		return
	}
	policy, managed := s.policiesByHash[hash]
	if !managed {
		return
	}
	now := s.now()
	u := s.usageByHash[policy.PrincipalID]
	if u == nil {
		u = &usage{}
		s.usageByHash[policy.PrincipalID] = u
	}
	resetWindows(u, now)
	u.Daily.Tokens += tokens
	u.Weekly.Tokens += tokens
	s.dirty = true
	if !s.flushScheduled && (s.lastFlush.IsZero() || now.Sub(s.lastFlush) >= 15*time.Second) {
		s.flushScheduled = true
		go s.Flush()
	}
}

// Flush persists accumulated usage without rewriting on every request.
func (s *Store) Flush() {
	release, err := acquireFileLock(s.stateFile)
	if err != nil {
		s.mu.Lock()
		s.flushScheduled = false
		s.mu.Unlock()
		return
	}
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushScheduled = false
	if !s.dirty {
		return
	}
	_ = s.refreshStateLocked(true)
	_ = s.saveLocked()
}

func (s *Store) Status() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	managedActive := 0
	for hash := range s.activeByHash {
		if _, ok := s.policiesByHash[hash]; ok {
			managedActive++
		}
	}
	return map[string]any{
		"mode":            "native-access",
		"native_keys":     len(s.activeByHash),
		"managed_active":  managedActive,
		"orphan_policies": len(s.policiesByHash) - managedActive,
		"keys_file":       s.keysFile,
	}
}
