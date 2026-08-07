package oidc

// ProviderType identifies a provided known OIDC provider.
type ProviderType string

const (
	// ProviderTypeAzure is the provider for Microsoft Azure.
	ProviderTypeAzure ProviderType = "azure"
)

// supportedProviderTypes is a map of all supported provider types.
var supportedProviderTypes = map[ProviderType]bool{
	ProviderTypeAzure: true,
}

// SupportedProviderType returns true if the given provider type is supported.
func SupportedProviderType(p ProviderType) bool {
	return supportedProviderTypes[p]
}
