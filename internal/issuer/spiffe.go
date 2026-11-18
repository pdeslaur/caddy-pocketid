package issuer

import (
	"context"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// ClientAssertionType is how a token request names a JWT client assertion
// (RFC 7523).
const ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// svidTimeout bounds fetching a JWT-SVID, so a missing agent fails the login
// instead of hanging it.
const svidTimeout = 5 * time.Second

// FetchSVID fetches a JWT-SVID for audience from the SPIFFE Workload API at
// SPIFFE_ENDPOINT_SOCKET.
func FetchSVID(ctx context.Context, audience string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, svidTimeout)
	defer cancel()
	svid, err := workloadapi.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience})
	if err != nil {
		return "", fmt.Errorf("fetching JWT-SVID: %w", err)
	}
	return svid.Marshal(), nil
}
