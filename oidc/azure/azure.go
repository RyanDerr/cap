package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

const (
	// claimNames is the OIDC "_claim_names" member (OIDC Core 1.0, Section 5.6.2).
	// Azure populates this field to signal a groups overage condition when a user
	// belongs to more than 200 groups.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims
	claimNames = "_claim_names"

	// claimSources is the OIDC "_claim_sources" member (OIDC Core 1.0, Section 5.6.2).
	// When a groups overage is present, Azure sets this to a map whose keys match
	// the values in _claim_names and whose entries each carry an "endpoint" URL.
	claimSources = "_claim_sources"

	// claimNameGroups is the Azure defined key within _claim_names that indicates
	// the groups claim has been distributed due to token size constraints.
	claimNameGroups = "groups"

	// microsoftGraphHost is the current Microsoft Graph API host for the
	// Global (commercial) cloud.
	microsoftGraphHost = "graph.microsoft.com"

	// microsoftGraphUSHost is the current Microsoft Graph API host for the
	// US Government L4 (GCC High) cloud.
	microsoftGraphUSHost = "graph.microsoft.us"

	// microsoftGraphDoDHost is the current Microsoft Graph API host for the
	// US Government L5 (DoD) cloud.
	microsoftGraphDoDHost = "dod-graph.microsoft.us"

	// microsoftGraphChinaHost is the current Microsoft Graph API host for the
	// China (21Vianet) cloud.
	microsoftGraphChinaHost = "microsoftgraph.chinacloudapi.cn"

	// azureADGraphHost is the deprecated Azure Active Directory Graph API host
	// for the Global (commercial) cloud. Azure still issues tokens that reference
	// this host during the migration period.
	//
	// See: https://learn.microsoft.com/en-us/graph/migrate-azure-ad-graph-request-differences
	azureADGraphHost = "graph.windows.net"

	// azureADGraphUSHost is the deprecated Azure Active Directory Graph API host
	// shared by both US Government L4 (GCC High) and US Government L5 (DoD) clouds.
	// Because both clouds share this host, tokens presenting this deprecated endpoint
	// are mapped to the GCC High (L4) Microsoft Graph host. Tokens from DoD
	// deployments that have migrated to the current dod-graph.microsoft.us host
	// are routed correctly.
	//
	// See: https://learn.microsoft.com/en-us/graph/migrate-azure-ad-graph-request-differences
	azureADGraphUSHost = "graph.microsoftazure.us"

	// azureADGraphChinaHost is the deprecated Azure Active Directory Graph API
	// host for the China (21Vianet) cloud.
	//
	// See: https://learn.microsoft.com/en-us/graph/migrate-azure-ad-graph-request-differences
	azureADGraphChinaHost = "graph.chinacloudapi.cn"

	// graphMemberGroupsPath is the Microsoft Graph v1.0 path for fetching all
	// transitive group memberships of the authenticated user in a single POST
	// request. Returns up to 11,000 group IDs. If that limit is exceeded the
	// API returns a 400 with Directory_ResultSizeLimitExceeded.
	//
	// See: https://learn.microsoft.com/en-us/graph/api/directoryobject-getmembergroups?view=graph-rest-1.0
	graphMemberGroupsPath = "/v1.0/me/getMemberGroups"
)

// graphMemberGroupsResponse is the JSON response shape returned by the
// Microsoft Graph getMemberGroups action.
type graphMemberGroupsResponse struct {
	Value []string `json:"value"`
}

// FetchDistributedAzureGroupClaims fetches group memberships for the
// authenticated user when Azure's groups overage condition is present.
// Returns nil if the groups overage indicator is not found in claims.
//
// See: https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference#groups-overage-claim
func FetchDistributedAzureGroupClaims(ctx context.Context, client *http.Client, token *oauth2.Token, claims map[string]interface{}) (map[string]interface{}, error) {
	const op = "FetchDistributedAzureGroupClaims"
	switch {
	case client == nil:
		return nil, fmt.Errorf("%s: http client is nil: %w", op, ErrNilParameter)
	case token == nil:
		return nil, fmt.Errorf("%s: token is nil: %w", op, ErrNilParameter)
	}

	host, ok := parseGroupsOverageHost(claims)
	if !ok {
		return nil, nil
	}
	groupIds, err := fetchGroupIDs(ctx, client, token, graphGroupsURLForHost(host))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return map[string]interface{}{claimNameGroups: groupIds}, nil
}

// fetchGroupIDs fetches all transitive group IDs for the authenticated user
// from the Microsoft Graph getMemberGroups API at the given url.
func fetchGroupIDs(ctx context.Context, client *http.Client, token *oauth2.Token, groupsURL string) ([]string, error) {
	const op = "fetchGroupIDs"
	switch {
	case client == nil:
		return nil, fmt.Errorf("%s: http client is nil: %w", op, ErrNilParameter)
	case token == nil:
		return nil, fmt.Errorf("%s: token is nil: %w", op, ErrNilParameter)
	case token.AccessToken == "":
		return nil, fmt.Errorf("%s: token access token is empty: %w", op, ErrInvalidParameter)
	}

	body, err := json.Marshal(map[string]bool{"securityEnabledOnly": false})
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal request body: %w", op, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, groupsURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("%s: unable to read response body: %w", op, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s: %s", op, resp.Status, respBody)
	}

	var result graphMemberGroupsResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("%s: failed to unmarshal groups response: %w", op, err)
	}
	return result.Value, nil
}

// parseGroupsOverageHost parses the Azure groups overage distributed claim
// from the given claims map and returns the validated Microsoft Graph host.
// It walks the OIDC distributed-claim structure:
//
//	_claim_names.groups -> source key -> _claim_sources[key].endpoint -> host
//
// The host is validated against the set of known Microsoft Graph and Azure AD
// Graph hosts across all supported clouds. Returns ("", false) if any step
// fails or if the endpoint host is not a known Microsoft Graph host.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims
// See: https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference#groups-overage-claim
func parseGroupsOverageHost(claims map[string]interface{}) (string, bool) {
	names, ok := claims[claimNames].(map[string]interface{})
	if !ok {
		return "", false
	}
	sourceKey, ok := names[claimNameGroups].(string)
	if !ok || sourceKey == "" {
		return "", false
	}
	sources, ok := claims[claimSources].(map[string]interface{})
	if !ok {
		return "", false
	}
	source, ok := sources[sourceKey].(map[string]interface{})
	if !ok {
		return "", false
	}
	endpoint, ok := source["endpoint"].(string)
	if !ok || endpoint == "" {
		return "", false
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", false
	}
	if !isMicrosoftGraphHost(u.Host) {
		return "", false
	}
	return u.Host, true
}

// graphGroupsURLForHost returns the Microsoft Graph getMemberGroups URL for
// the given host. Deprecated AAD Graph hosts are mapped to their modern
// Microsoft Graph equivalents. The commercial Microsoft Graph URL is returned
// for any unrecognized host.
func graphGroupsURLForHost(host string) string {
	switch host {
	case microsoftGraphUSHost, azureADGraphUSHost:
		return "https://" + microsoftGraphUSHost + graphMemberGroupsPath
	case microsoftGraphDoDHost:
		return "https://" + microsoftGraphDoDHost + graphMemberGroupsPath
	case microsoftGraphChinaHost, azureADGraphChinaHost:
		return "https://" + microsoftGraphChinaHost + graphMemberGroupsPath
	default:
		return "https://" + microsoftGraphHost + graphMemberGroupsPath
	}
}

// isMicrosoftGraphHost reports whether host is a known Microsoft Graph or
// Azure AD Graph host across all supported clouds, including deprecated hosts
// that Azure may still emit during the AAD Graph migration period.
//
// See: https://learn.microsoft.com/en-us/graph/deployments
func isMicrosoftGraphHost(host string) bool {
	switch host {
	case microsoftGraphHost, microsoftGraphUSHost, microsoftGraphDoDHost,
		microsoftGraphChinaHost, azureADGraphHost, azureADGraphUSHost,
		azureADGraphChinaHost:
		return true
	}
	return false
}
