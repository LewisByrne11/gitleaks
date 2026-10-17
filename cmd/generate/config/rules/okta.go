package rules

import (
	"strings"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func OktaAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "okta-access-token",
		Description: "Identified an Okta Access Token, which may compromise identity management services and user authentication data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{`(?-i:[Oo]kta|OKTA)`}, `00[\w=\-]{40}`, false),
		Entropy:     4,
		Keywords: []string{
			"okta",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("okta", secrets.NewSecret(`00[\w=\-]{40}`))
	tps = append(tps,
		`"oktaApiToken": "00ebObu4zSNkyc6dimLvUwq4KpTEop-PCEnnfSTpD3",`,       // gitleaks:allow
		`			var OktaApiToken = "00fWkOjwwL9xiFd-Vfgm_ePATIRxVj852Iblbb1DS_";`, // gitleaks:allow
	)
	fps := []string{
		`oktaKey = 00000000000000000000000000000000000TUVWXYZ`,   // low entropy
		`rookTable = 0023452Lllk2KqjLBvaxANWEgTd7bqjsxjo8aZj0wd`, // wrong case
	}
	return utils.Validate(r, tps, fps)
}

func OktaClientID() *config.Rule {
	r := config.Rule{
		RuleID:      "okta-client-id",
		Description: "Identified an Okta OAuth 2.0 Client ID.",
		Regex:       regexp.MustCompile(`(?:[^a-zA-Z0-9_-]|^)(0oa[a-zA-Z0-9]{17})(?:[^a-zA-Z0-9_-]|$)`),
		Entropy:     3,
		Keywords: []string{
			"0oa",
		},
		SkipReport: true,
	}

	tps := []string{
		`client_id = "0oakDa9U4UqGWlG6g3Ot"`,
	}
	fps := []string{
		`client_id = "0oa00000000000000000"`,     // low entropy
		`client_id = "0obkDa9U4UqGWlG6g3Ot"`,     // wrong prefix
		`client_id = "0oakDa9U4UqGWlG6g3Ot999"`,  // too long (partial match guard)
		`client_id = "foo-0oakDa9U4UqGWlG6g3Ot"`, // hyphen-prefixed partial match
	}
	return utils.Validate(r, tps, fps)
}

func OktaOAuthClientSecret() *config.Rule {
	withinLines := 20
	// Delimiters consume a non-secret char instead of using \b, since \b breaks on secrets
	// starting or ending in '-' (a non-word char that is also part of the secret charset).
	r := config.Rule{
		RuleID:      "okta-oauth-client-secret",
		Description: "Identified an Okta OAuth 2.0 Client Secret, which could allow unauthorized access to Okta applications and APIs.",
		Regex: regexp.MustCompile(
			`(?i)[\w.-]{0,50}?(?:client[_-]?secret|(?-i:[Oo]kta|OKTA)[_.-]?(?:[a-z0-9_.-]+[_.-])?secret)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9_-]{40,64})(?:[^a-zA-Z0-9_-]|$)`,
		),
		Entropy: 3.5,
		Keywords: []string{
			"0oa",
		},
		RequiredRules: []*config.Required{
			{
				RuleID:      "okta-client-id",
				WithinLines: &withinLines,
			},
		},
	}

	tps := []string{
		"okta_client_id = '0oakDa9U4UqGWlG6g3Ot'\nclient_secret: 'OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW'",
		"client_id = \"0oakDa9U4UqGWlG6g3Ot\"\nclient_secret = \"wj9bOsLK0BRNJqy7KMMnaE7m8qrW51bPO2n1-PYvkOmhHRYgcuOecQkEwq9MPYa5\"",
		"client_id = \"0oakDa9U4UqGWlG6g3Ot\"\nclient_secret = \"-u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLz\"",
		"client_id = \"0oakDa9U4UqGWlG6g3Ot\"\nclient_secret = \"u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLz-\"",
		"client_id = \"0oakDa9U4UqGWlG6g3Ot\"\nclient_secret = \"-u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLzd\"",
		"client_id = \"0oakDa9U4UqGWlG6g3Ot\"\nclient_secret = \"u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLzd-\"",
	}
	fps := []string{
		// Missing Okta client ID
		"client_id = 'not_an_okta_client_id'\nclient_secret: 'OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW'",
		// Invalid client ID prefix (0ob instead of 0oa)
		"client_id = '0obkDa9U4UqGWlG6g3Ot'\nclient_secret: 'OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW'",
		// Partial match inside a longer token containing 0oa...
		"client_id = '0oakDa9U4UqGWlG6g3OtExtraChars'\nclient_secret: 'OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW'",
		// Low entropy secret
		"client_id = '0oakDa9U4UqGWlG6g3Ot'\nclient_secret: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'",
		// Client ID outside withinLines (20) proximity window
		"client_id = '0oakDa9U4UqGWlG6g3Ot'\n" + strings.Repeat("\n", 25) + "client_secret: 'OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW'",
	}
	return utils.ValidateComposite(r, []*config.Rule{OktaClientID()}, tps, fps)
}
