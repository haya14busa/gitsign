package main

import (
    "context"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "io"
    "net/http"
    "os"
    "strings"
    "time"

    cosignopts "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
    "github.com/sigstore/gitsign/internal/commands/verify"
    "github.com/sigstore/gitsign/internal/config"
    "github.com/sigstore/gitsign/internal/gitsign"
)

type verification struct {
    Payload   string `json:"payload"`
    Signature string `json:"signature"`
    Verified  bool   `json:"verified"`
    Reason    string `json:"reason"`
}

// Git refs API response
type gitRef struct {
    Ref    string `json:"ref"`
    NodeID string `json:"node_id"`
    Object struct {
        Type string `json:"type"`
        SHA  string `json:"sha"`
        URL  string `json:"url"`
    } `json:"object"`
}

// Git tag object API response
type gitTag struct {
    Tag          string       `json:"tag"`
    SHA          string       `json:"sha"`
    Object       struct{ Type, SHA string } `json:"object"`
    Message      string       `json:"message"`
    Verification verification `json:"verification"`
}

// Repo commit (high-level) response
type repoCommit struct {
    SHA          string       `json:"sha"`
    Verification verification `json:"verification"`
}

func ghGet(ctx context.Context, client *http.Client, token, path string) ([]byte, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Accept", "application/vnd.github+json")
    if token != "" {
        req.Header.Set("Authorization", "Bearer "+token)
    }
    // GitHub API version header (optional)
    req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
        return nil, fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, string(b))
    }
    return io.ReadAll(resp.Body)
}

func fetchTagVerification(ctx context.Context, client *http.Client, token, owner, repo, tag string) (payload, signature string, err error) {
    base := "https://api.github.com"
    // Resolve annotated tag object
    // GET /repos/{owner}/{repo}/git/refs/tags/{tag}
    refURL := fmt.Sprintf("%s/repos/%s/%s/git/refs/tags/%s", base, owner, repo, tag)
    b, err := ghGet(ctx, client, token, refURL)
    if err != nil {
        return "", "", err
    }
    var r gitRef
    if err := json.Unmarshal(b, &r); err != nil {
        return "", "", err
    }
    if !strings.EqualFold(r.Object.Type, "tag") {
        return "", "", fmt.Errorf("tag %q is not annotated (type=%q)", tag, r.Object.Type)
    }

    // Get tag object with verification
    // GET /repos/{owner}/{repo}/git/tags/{sha}
    tagURL := fmt.Sprintf("%s/repos/%s/%s/git/tags/%s", base, owner, repo, r.Object.SHA)
    b, err = ghGet(ctx, client, token, tagURL)
    if err != nil {
        return "", "", err
    }
    var t gitTag
    if err := json.Unmarshal(b, &t); err != nil {
        return "", "", err
    }
    if t.Verification.Signature == "" || t.Verification.Payload == "" {
        return "", "", errors.New("no signature/payload in tag verification")
    }
    return t.Verification.Payload, t.Verification.Signature, nil
}

func fetchCommitVerification(ctx context.Context, client *http.Client, token, owner, repo, ref string) (payload, signature string, err error) {
    base := "https://api.github.com"
    // GET /repos/{owner}/{repo}/commits/{ref}
    u := fmt.Sprintf("%s/repos/%s/%s/commits/%s", base, owner, repo, ref)
    b, err := ghGet(ctx, client, token, u)
    if err != nil {
        return "", "", err
    }
    var c repoCommit
    if err := json.Unmarshal(b, &c); err != nil {
        return "", "", err
    }
    if c.Verification.Signature == "" || c.Verification.Payload == "" {
        return "", "", errors.New("no signature/payload in commit verification")
    }
    return c.Verification.Payload, c.Verification.Signature, nil
}

func main() {
    var (
        owner   = flag.String("owner", "", "GitHub owner (org/user)")
        repo    = flag.String("repo", "", "GitHub repository name")
        tag     = flag.String("tag", "", "Tag name to verify (annotated tag)")
        commit  = flag.String("commit", "", "Commit SHA or ref to verify")
        token   = flag.String("token", os.Getenv("GITHUB_TOKEN"), "GitHub token (or set GITHUB_TOKEN)")

        // Optional certificate claim checks (subset of cosign flags)
        certIdentity      = flag.String("certificate-identity", "", "expected certificate identity (email/DNS/IP/URI)")
        certIdentityRegex = flag.String("certificate-identity-regexp", "", "expected certificate identity regex")
        certIssuer        = flag.String("certificate-oidc-issuer", "", "expected OIDC issuer")
        certIssuerRegex   = flag.String("certificate-oidc-issuer-regexp", "", "expected OIDC issuer regex")
        ghaTrigger        = flag.String("certificate-github-workflow-trigger", "", "expected GHA workflow trigger")
        ghaSHA            = flag.String("certificate-github-workflow-sha", "", "expected GHA workflow sha")
        ghaName           = flag.String("certificate-github-workflow-name", "", "expected GHA workflow name")
        ghaRepo           = flag.String("certificate-github-workflow-repository", "", "expected GHA workflow repository")
        ghaRef            = flag.String("certificate-github-workflow-ref", "", "expected GHA workflow ref")
        ignoreSCT         = flag.Bool("insecure-ignore-sct", false, "do not require embedded SCT")
    )
    flag.Parse()

    if *owner == "" || *repo == "" || (*tag == "" && *commit == "") || (*tag != "" && *commit != "") {
        fmt.Fprintln(os.Stderr, "Usage: gitsign-verify-remote --owner <org> --repo <repo> [--tag <name> | --commit <sha>] [claim flags...]")
        flag.PrintDefaults()
        os.Exit(2)
    }

    ctx := context.Background()
    httpClient := &http.Client{Timeout: 30 * time.Second}

    // Fetch payload/signature from GitHub API
    var (
        payload   string
        signature string
        err       error
    )
    if *tag != "" {
        payload, signature, err = fetchTagVerification(ctx, httpClient, *token, *owner, *repo, *tag)
    } else {
        payload, signature, err = fetchCommitVerification(ctx, httpClient, *token, *owner, *repo, *commit)
    }
    if err != nil {
        fmt.Fprintln(os.Stderr, "error fetching verification:", err)
        os.Exit(1)
    }

    // Build cosign verify opts for certificate claim checks
    var opts cosignopts.CertVerifyOptions
    opts.CertIdentity = *certIdentity
    opts.CertIdentityRegexp = *certIdentityRegex
    opts.CertOidcIssuer = *certIssuer
    opts.CertOidcIssuerRegexp = *certIssuerRegex
    opts.CertGithubWorkflowTrigger = *ghaTrigger
    opts.CertGithubWorkflowSha = *ghaSHA
    opts.CertGithubWorkflowName = *ghaName
    opts.CertGithubWorkflowRepository = *ghaRepo
    opts.CertGithubWorkflowRef = *ghaRef
    opts.IgnoreSCT = *ignoreSCT

    // Load gitsign config (env/defaults). This does not require a local .git.
    // If unavailable, fall back to defaults.
    var cfg *config.Config
    if c, err := config.Get(); err == nil {
        cfg = c
    } else {
        // Defaults matching config.Get defaults
        cfg = &config.Config{
            Fulcio:    "https://fulcio.sigstore.dev",
            Rekor:     "https://rekor.sigstore.dev",
            ClientID:  "sigstore",
            Issuer:    "https://oauth2.sigstore.dev/auth",
            RekorMode: "online",
        }
    }

    // Verify using gitsign verifier
    v, err := gitsign.NewVerifierWithCosignOpts(ctx, cfg, &opts)
    if err != nil {
        fmt.Fprintln(os.Stderr, "error creating verifier:", err)
        os.Exit(1)
    }
    summary, err := v.Verify(ctx, []byte(payload), []byte(signature), true)
    if err != nil {
        fmt.Fprintln(os.Stderr, "verification failed:", err)
        os.Exit(1)
    }

    // Print result like `gitsign verify`
    verify.PrintSummary(os.Stdout, summary)
}

