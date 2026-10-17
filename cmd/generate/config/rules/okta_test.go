package rules

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/detect"
)

func TestOktaRules(t *testing.T) {
	d, err := detect.NewDetectorDefaultConfig()
	require.NoError(t, err)

	t.Run("true positives", func(t *testing.T) {
		tests := []struct {
			name       string
			input      string
			wantRuleID string
			wantSecret string
		}{
			{
				name:       "ssws access token",
				input:      `"oktaApiToken": "00ebObu4zSNkyc6dimLvUwq4KpTEop-PCEnnfSTpD3"`,
				wantRuleID: "okta-access-token",
				wantSecret: "00ebObu4zSNkyc6dimLvUwq4KpTEop-PCEnnfSTpD3",
			},
			{
				name: "oauth client credentials (40 chars)",
				input: `okta_domain = "a254u0kjk-y64jh762weozo374t.okta.com"
okta_client_id = "0oakDa9U4UqGWlG6g3Ot"
client_secret: "OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW"`,
				wantRuleID: "okta-oauth-client-secret",
				wantSecret: "OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW",
			},
			{
				name: "oauth client credentials (64 chars OIE / v1 clients format)",
				input: `{
  "client_id": "0oakDa9U4UqGWlG6g3Ot",
  "client_secret": "wj9bOsLK0BRNJqy7KMMnaE7m8qrW51bPO2n1-PYvkOmhHRYgcuOecQkEwq9MPYa5"
}`,
				wantRuleID: "okta-oauth-client-secret",
				wantSecret: "wj9bOsLK0BRNJqy7KMMnaE7m8qrW51bPO2n1-PYvkOmhHRYgcuOecQkEwq9MPYa5",
			},
			{
				name: "oauth client_secret (40 chars) starting with hyphen",
				input: `client_id = "0oakDa9U4UqGWlG6g3Ot"
client_secret = "-u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLz"`,
				wantRuleID: "okta-oauth-client-secret",
				wantSecret: "-u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLz",
			},
			{
				name: "oauth client_secret (40 chars) ending with hyphen",
				input: `client_id = "0oakDa9U4UqGWlG6g3Ot"
client_secret = "u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLz-"`,
				wantRuleID: "okta-oauth-client-secret",
				wantSecret: "u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLz-",
			},
			{
				name: "oauth client_secret (41 chars) starting with hyphen",
				input: `client_id = "0oakDa9U4UqGWlG6g3Ot"
client_secret = "-u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLzd"`,
				wantRuleID: "okta-oauth-client-secret",
				wantSecret: "-u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLzd",
			},
			{
				name: "oauth client_secret (41 chars) ending with hyphen",
				input: `client_id = "0oakDa9U4UqGWlG6g3Ot"
client_secret = "u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLzd-"`,
				wantRuleID: "okta-oauth-client-secret",
				wantSecret: "u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLzd-",
			},
			{
				name: "oauth client_secret with alphabetical-only characters (missed by generic-api-key)",
				input: `client_id = "0oakDa9U4UqGWlG6g3Ot"
client_secret = "OhbVrpoiVgRVaIfLBcbfnoGMbJmTPSIAoCLrZaaW"`,
				wantRuleID: "okta-oauth-client-secret",
				wantSecret: "OhbVrpoiVgRVaIfLBcbfnoGMbJmTPSIAoCLrZaaW",
			},
			{
				name:       "oauth client_secret at exact withinLines=20 boundary",
				input:      "client_id = \"0oakDa9U4UqGWlG6g3Ot\"" + strings.Repeat("\n", 20) + "client_secret = \"OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW\"",
				wantRuleID: "okta-oauth-client-secret",
				wantSecret: "OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW",
			},
			{
				name: "Spring Boot application.properties format",
				input: `okta.oauth2.issuer=https://dev-123456.okta.com/oauth2/default
okta.oauth2.client-id=0oakDa9U4UqGWlG6g3Ot
okta.oauth2.client-secret=OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW`,
				wantRuleID: "okta-oauth-client-secret",
				wantSecret: "OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW",
			},
			{
				name: "Okta SDK .okta.yaml camelCase format",
				input: `okta:
  client:
    orgUrl: "https://dev-123456.okta.com"
    clientId: "0oakDa9U4UqGWlG6g3Ot"
    clientSecret: "OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW"`,
				wantRuleID: "okta-oauth-client-secret",
				wantSecret: "OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW",
			},
			{
				name: "Node.js / TypeScript Okta SDK object literal",
				input: `const oktaClient = new okta.Client({
  orgUrl: 'https://dev-123456.oktapreview.com',
  clientId: '0oakDa9U4UqGWlG6g3Ot',
  clientSecret: 'OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW',
});`,
				wantRuleID: "okta-oauth-client-secret",
				wantSecret: "OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				findings := d.DetectString(tc.input)
				var matched []string
				for _, f := range findings {
					if f.RuleID == tc.wantRuleID {
						matched = append(matched, f.Secret)
					}
					assert.NotEqual(t, "okta-client-id", f.RuleID, "okta-client-id has skipReport=true and must not be reported standalone")
				}
				assert.Equal(t, []string{tc.wantSecret}, matched)
			})
		}
	})

	t.Run("false positives", func(t *testing.T) {
		tests := []struct {
			name  string
			input string
		}{
			{
				name:  "standalone okta client_id without secret does not report",
				input: `okta_client_id = "0oakDa9U4UqGWlG6g3Ot"`,
			},
			{
				name: "non-okta client_id (wrong prefix 0ob)",
				input: `client_id = "0obkDa9U4UqGWlG6g3Ot"
client_secret = "OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW"`,
			},
			{
				name: "partial match client_id inside longer alphanumeric string",
				input: `client_id = "0oakDa9U4UqGWlG6g3OtExtraChars"
client_secret = "OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW"`,
			},
			{
				name: "partial match client_id with hyphen prefix",
				input: `client_id = "prefix-0oakDa9U4UqGWlG6g3Ot"
client_secret = "OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW"`,
			},
			{
				name: "low entropy client_secret",
				input: `client_id = "0oakDa9U4UqGWlG6g3Ot"
client_secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`,
			},
			{
				name:  "okta client_id outside withinLines=20 proximity window (21 lines apart)",
				input: "client_id = \"0oakDa9U4UqGWlG6g3Ot\"" + strings.Repeat("\n", 21) + "client_secret = \"OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW\"",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				findings := d.DetectString(tc.input)
				for _, f := range findings {
					assert.NotContains(t, []string{"okta-client-id", "okta-oauth-client-secret"}, f.RuleID)
				}
			})
		}
	})
}
