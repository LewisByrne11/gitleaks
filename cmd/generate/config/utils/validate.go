// == WARNING ==
// These functions are used to generate GitLeak's default config.
// You are free to use these in your own project, HOWEVER, no API stability is guaranteed.

package utils

import (
	"strings"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/base"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/logging"
)

func Validate(rule config.Rule, truePositives []string, falsePositives []string) *config.Rule {
	return ValidateComposite(rule, nil, truePositives, falsePositives)
}

func ValidateComposite(rule config.Rule, requiredRules []*config.Rule, truePositives []string, falsePositives []string) *config.Rule {
	r := &rule
	evalRule := rule
	// If validating a helper rule in isolation, allow it to report so its regex/entropy can be validated.
	if len(requiredRules) == 0 && evalRule.SkipReport {
		evalRule.SkipReport = false
	}
	d := createRuleDetector(&evalRule, requiredRules...)
	for _, tp := range truePositives {
		if len(d.DetectString(tp)) < 1 {
			logging.Fatal().
				Str("rule", r.RuleID).
				Str("value", tp).
				Str("regex", r.Regex.String()).
				Msg("Failed to Validate. True positive was not detected by regex.")
		}
	}
	for _, fp := range falsePositives {
		findings := d.DetectString(fp)
		if len(findings) != 0 {
			logging.Fatal().
				Str("rule", r.RuleID).
				Str("value", fp).
				Str("regex", r.Regex.String()).
				Msg("Failed to Validate. False positive was detected by regex.")
		}
	}
	// Ensure keywords on r itself are normalized just like createRuleDetector did on evalRule.
	r.Keywords = evalRule.Keywords
	return r
}

func ValidateWithPaths(rule config.Rule, truePositives map[string]string, falsePositives map[string]string) *config.Rule {
	r := &rule
	d := createRuleDetector(r)
	for path, tp := range truePositives {
		f := detect.Fragment{Raw: tp, FilePath: path}
		if len(d.Detect(f)) != 1 {
			logging.Fatal().
				Str("rule", r.RuleID).
				Str("value", tp).
				Str("regex", r.Regex.String()).
				Str("path", r.Path.String()).
				Msg("Failed to Validate. True positive was not detected by regex and/or path.")
		}
	}
	for path, fp := range falsePositives {
		f := detect.Fragment{Raw: fp, FilePath: path}
		if len(d.Detect(f)) != 0 {
			logging.Fatal().
				Str("rule", r.RuleID).
				Str("value", fp).
				Str("regex", r.Regex.String()).
				Str("path", r.Path.String()).
				Msg("Failed to Validate. False positive was detected by regex and/or path.")
		}
	}
	return r
}

func createRuleDetector(r *config.Rule, auxRules ...*config.Rule) *detect.Detector {
	// normalize keywords like in the config package
	var (
		uniqueKeywords = make(map[string]struct{})
		rules          = make(map[string]config.Rule, 1+len(auxRules))
	)
	allRules := append([]*config.Rule{r}, auxRules...)
	for _, rule := range allRules {
		var keywords []string
		seen := make(map[string]struct{})
		for _, keyword := range rule.Keywords {
			k := strings.ToLower(keyword)
			uniqueKeywords[k] = struct{}{}
			if _, ok := seen[k]; ok {
				continue
			}
			keywords = append(keywords, k)
			seen[k] = struct{}{}
		}
		rule.Keywords = keywords
		rules[rule.RuleID] = *rule
	}

	cfg := base.CreateGlobalConfig()
	cfg.Rules = rules
	cfg.Keywords = uniqueKeywords
	for _, a := range cfg.Allowlists {
		if err := a.Validate(); err != nil {
			logging.Fatal().Err(err).Msg("invalid global allowlist")
		}
	}
	return detect.NewDetector(cfg)
}
