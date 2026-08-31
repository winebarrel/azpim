package azpim

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// AuthEndpoint is the Microsoft identity platform endpoint used to sign in.
const AuthEndpoint = "https://login.microsoftonline.com"

// signInTimeout bounds how long a pending sign-in holds the loopback listener.
const signInTimeout = 5 * time.Minute

// Authenticator obtains delegated tokens by the authorization code flow with
// PKCE, redirecting to a loopback address.
//
// The device code flow would need no browser plumbing, but tenants routinely
// block it outright with a Conditional Access authentication-flow policy, and
// such a block cannot be worked around from the client. The browser flow is
// what `Connect-MgGraph` uses by default and passes device-compliance
// conditions, because it runs in the user's own browser session.
//
// This is a public client: no secret is held, and PKCE is what binds the
// redirect back to this process.
type Authenticator struct {
	TenantID string
	ClientID string

	// Endpoint and CacheDir default to the real ones; tests set them.
	Endpoint string
	CacheDir string

	HTTP      *http.Client
	ErrOutput io.Writer

	// Browser opens the sign-in page. Tests replace it to drive the redirect
	// without a real browser.
	Browser func(target string) error
}

// Client returns a Graph client holding a token good for the given scopes.
//
// The client is given a way back here so that a call refused for want of an
// authentication context can be answered with a token that carries one.
func (a *Authenticator) Client(ctx context.Context, scopes []string) (*Client, error) {
	token, err := a.Token(ctx, scopes)

	if err != nil {
		return nil, err
	}

	return &Client{
		BaseURL: GraphBaseURL,
		Token:   token,
		HTTP:    a.HTTP,
		Reauth: func(ctx context.Context, claims string) (string, error) {
			return a.TokenWithClaims(ctx, scopes, claims)
		},
	}, nil
}

// cachedToken is what is persisted between runs.
type cachedToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at"`
}

// tokenResponse is the identity platform's reply at the token endpoint.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int64  `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (a *Authenticator) endpoint() string {
	if a.Endpoint != "" {
		return a.Endpoint
	}

	return AuthEndpoint
}

func (a *Authenticator) httpClient() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}

	return http.DefaultClient
}

func (a *Authenticator) errOutput() io.Writer {
	if a.ErrOutput != nil {
		return a.ErrOutput
	}

	return io.Discard
}

// cachePath names the cache file for a scope set and claims challenge.
//
// The scopes are part of the name because a cached token is only useful for
// the scopes it was issued with. Keying on them means asking for a different
// area re-authenticates instead of silently reusing a token that Graph will
// reject. Claims are keyed the same way and for the same reason: a token
// issued for a challenge is a different token, and filing it separately keeps
// it from being handed to a plain call, and keeps the plain token from being
// handed back to the challenge that just refused it.
func (a *Authenticator) cachePath(scopes []string, claims string) (string, error) {
	dir := a.CacheDir

	if dir == "" {
		base, err := os.UserCacheDir()

		if err != nil {
			return "", err
		}

		dir = filepath.Join(base, "azpim")
	}

	key := strings.Join(scopes, " ")

	if claims != "" {
		key += " " + claims
	}

	sum := sha256.Sum256([]byte(key))
	name := fmt.Sprintf("%s-%s.json", a.TenantID, base64.RawURLEncoding.EncodeToString(sum[:6]))

	return filepath.Join(dir, name), nil
}

// Token returns an access token for the given scopes, reusing a cached one and
// refreshing it silently where possible.
func (a *Authenticator) Token(ctx context.Context, scopes []string) (string, error) {
	return a.TokenWithClaims(ctx, scopes, "")
}

// TokenWithClaims returns an access token issued to satisfy a claims
// challenge, or an ordinary one when claims is empty.
//
// The claims travel with the sign-in request, which is what lets the identity
// platform ask for whatever the authentication context requires -- a second
// factor, a compliant device -- and then stamp the acrs claim PIM checks for
// into the token. A refresh cannot do that, so a challenge goes straight to
// the browser rather than trying silently first.
func (a *Authenticator) TokenWithClaims(ctx context.Context, scopes []string, claims string) (string, error) {
	path, err := a.cachePath(scopes, claims)

	if err != nil {
		return "", err
	}

	cached := readCache(path)

	// The margin keeps a token from expiring between this check and the call
	// it is about to be used for.
	if cached != nil && cached.ExpiresAt > time.Now().Add(2*time.Minute).Unix() {
		return cached.AccessToken, nil
	}

	if cached != nil && cached.RefreshToken != "" && claims == "" {
		token, err := a.redeem(ctx, url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {a.ClientID},
			"refresh_token": {cached.RefreshToken},
			"scope":         {strings.Join(scopes, " ")},
		})

		if err == nil {
			return a.store(path, token)
		}
	}

	token, err := a.signIn(ctx, scopes, claims)

	if err != nil {
		return "", err
	}

	return a.store(path, token)
}

func (a *Authenticator) store(path string, token *tokenResponse) (string, error) {
	if err := writeCache(path, &cachedToken{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(token.ExpiresIn) * time.Second).Unix(),
	}); err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

// signIn runs the interactive half of the flow.
func (a *Authenticator) signIn(ctx context.Context, scopes []string, claims string) (*tokenResponse, error) {
	if a.ClientID == "" || a.TenantID == "" {
		return nil, errors.New("both a tenant and a client id are required to sign in")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		return nil, err
	}

	defer listener.Close() //nolint:errcheck

	// The application registers "http://localhost" as a redirect, for which the
	// identity platform accepts any port, so an ephemeral one avoids colliding
	// with whatever else is listening.
	redirect := fmt.Sprintf("http://localhost:%d", listener.Addr().(*net.TCPAddr).Port)

	verifier, err := randomString()

	if err != nil {
		return nil, err
	}

	challenge := sha256.Sum256([]byte(verifier))

	state, err := randomString()

	if err != nil {
		return nil, err
	}

	params := url.Values{
		"client_id":             {a.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {redirect},
		"response_mode":         {"query"},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
		"prompt":                {"select_account"},
	}

	// The challenge is passed on verbatim: its contents are the tenant's, and
	// the identity platform is what has to make sense of them.
	if claims != "" {
		params.Set("claims", claims)
	}

	target := fmt.Sprintf("%s/%s/oauth2/v2.0/authorize?%s", a.endpoint(), a.TenantID, params.Encode())

	results := make(chan url.Values, 1)
	server := &http.Server{
		Handler:           http.HandlerFunc(redirectHandler(results)),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Serve always returns a non-nil error. Discarding it would turn a listener
	// that died on its own into a silent wait for a redirect that can no longer
	// arrive, so it is selected on below alongside the redirect itself.
	serveErr := make(chan error, 1)

	go func() { serveErr <- server.Serve(listener) }()

	defer server.Close() //nolint:errcheck

	fmt.Fprintf(a.errOutput(), "Opening the sign-in page. If it does not open, visit:\n%s\n", target) //nolint:errcheck

	if err := a.openBrowser(target); err != nil {
		return nil, err
	}

	var query url.Values

	select {
	case query = <-results:
	case err := <-serveErr:
		// The deferred Close runs only after this select, so reaching here
		// means the listener stopped by itself and no redirect is coming.
		return nil, fmt.Errorf("the loopback listener stopped before the sign-in completed: %w", err)
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(signInTimeout):
		return nil, errors.New("timed out waiting for the sign-in to complete")
	}

	// A mismatch means the redirect did not come from the request this process
	// started, so the code it carries is not ours to redeem.
	if query.Get("state") != state {
		return nil, errors.New("the sign-in response did not match the request and was discarded")
	}

	if code := query.Get("code"); code != "" {
		return a.redeem(ctx, url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {a.ClientID},
			"code":          {code},
			"redirect_uri":  {redirect},
			"code_verifier": {verifier},
			"scope":         {strings.Join(scopes, " ")},
		})
	}

	return nil, fmt.Errorf("sign-in failed: %s: %s", query.Get("error"), query.Get("error_description"))
}

func (a *Authenticator) openBrowser(target string) error {
	if a.Browser != nil {
		return a.Browser(target)
	}

	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", target).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", target).Start()
	default:
		return exec.Command("xdg-open", target).Start()
	}
}

// redeem exchanges a code or a refresh token for an access token.
func (a *Authenticator) redeem(ctx context.Context, form url.Values) (*tokenResponse, error) {
	target := fmt.Sprintf("%s/%s/oauth2/v2.0/token", a.endpoint(), a.TenantID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))

	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient().Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close() //nolint:errcheck

	var token tokenResponse

	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}

	if token.Error != "" {
		return nil, fmt.Errorf("token request failed: %s: %s", token.Error, token.ErrorDescription)
	}

	if token.AccessToken == "" {
		return nil, errors.New("the token response contained no access token")
	}

	return &token, nil
}

// redirectHandler hands the query back to the waiting flow and tells the
// browser it can be closed.
func redirectHandler(results chan<- url.Values) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		select {
		case results <- query:
		default:
		}

		message := "Signed in. You can close this tab and return to the terminal."

		if query.Get("code") == "" {
			message = "Sign-in failed: " + query.Get("error_description")
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body style=\"font-family:sans-serif;padding:3em\"><p>%s</p></body></html>", message) //nolint:errcheck
	}
}

func randomString() (string, error) {
	buf := make([]byte, 32)

	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func readCache(path string) *cachedToken {
	data, err := os.ReadFile(path)

	if err != nil {
		return nil
	}

	var token cachedToken

	if err := json.Unmarshal(data, &token); err != nil {
		return nil
	}

	return &token
}

// writeCache persists a token readable only by its owner, replacing the file
// atomically so a crash mid-write cannot leave a truncated one behind.
func writeCache(path string, token *cachedToken) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	data, err := json.Marshal(token)

	if err != nil {
		return err
	}

	tmp := path + ".tmp"

	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}

	return os.Rename(tmp, path)
}
