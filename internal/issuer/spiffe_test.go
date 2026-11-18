package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
)

const testSPIFFEID = "spiffe://example.org/svc/app"

// fakeWorkloadAPI serves JWT-SVIDs for testSPIFFEID, signed with a key of its
// own, standing in for a SPIRE agent.
type fakeWorkloadAPI struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	signer jose.Signer
}

// serveWorkloadAPI serves a fake Workload API until the test ends and points
// SPIFFE_ENDPOINT_SOCKET at it.
func serveWorkloadAPI(t *testing.T) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	// Not t.TempDir: its paths can be longer than a socket's may be.
	dir, err := os.MkdirTemp("", "workload")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "api.sock")
	lis, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(srv, &fakeWorkloadAPI{signer: signer})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix://"+socket)
}

func (a *fakeWorkloadAPI) FetchJWTSVID(_ context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	now := time.Now()
	token, err := jwt.Signed(a.signer).Claims(jwt.Claims{
		Subject:  testSPIFFEID,
		Audience: req.Audience,
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(5 * time.Minute)),
	}).Serialize()
	if err != nil {
		return nil, err
	}
	return &workload.JWTSVIDResponse{Svids: []*workload.JWTSVID{{SpiffeId: testSPIFFEID, Svid: token}}}, nil
}
