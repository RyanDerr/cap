package azure

import "errors"

var (
	ErrNilParameter     = errors.New("nil parameter")
	ErrInvalidParameter = errors.New("invalid parameter")
)
