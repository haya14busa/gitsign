package main

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	cmsproto "github.com/github/smimesign/ietf-cms/protocol"
	"github.com/go-openapi/strfmt"
	rekorpb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/protobuf/proto"
)

type verification struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type gitRef struct {
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
	} `json:"object"`
}

type gitTag struct {
	Verification verification `json:"verification"`
}

type repoCommit struct {
	Verification verification `json:"verification"`
}

func ghGet(ctx context.Context, client *http.Client, token, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
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

func fetchTagSig(ctx context.Context, client *http.Client, token, owner, repo, tag string) (payload, signature string, err error) {
	base := "https://api.github.com"
	refURL := fmt.Sprintf("%s/repos/%s/%s/git/refs/tags/%s", base, owner, repo, tag)
	b, err := ghGet(ctx, client, token, refURL)
	if err != nil {
		return "", "", err
	}
	var r gitRef
	if err := json.Unmarshal(b, &r); err != nil {
		return "", "", err
	}
	if r.Object.Type != "tag" {
		return "", "", fmt.Errorf("%s is not an annotated tag (type=%s)", tag, r.Object.Type)
	}
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

func fetchCommitSig(ctx context.Context, client *http.Client, token, owner, repo, ref string) (payload, signature string, err error) {
	base := "https://api.github.com"
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
		// Source selection
		sigPath = flag.String("sig-file", "", "Path to CMS/PKCS7 signature (PEM or DER).")
		owner   = flag.String("owner", "", "GitHub owner (org/user)")
		repo    = flag.String("repo", "", "GitHub repository name")
		tag     = flag.String("tag", "", "Annotated tag name to fetch from GitHub")
		commit  = flag.String("commit", "", "Commit SHA/ref to fetch from GitHub")
		token   = flag.String("token", os.Getenv("GITHUB_TOKEN"), "GitHub token (or set GITHUB_TOKEN)")
	)
	flag.Parse()

	ctx := context.Background()

	var (
		sigBytes []byte
		err      error
	)

	switch {
	case *sigPath != "":
		sigBytes, err = os.ReadFile(*sigPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read signature:", err)
			os.Exit(1)
		}
	case *owner != "" && *repo != "" && (*tag != "" || *commit != ""):
		httpClient := &http.Client{Timeout: 30 * time.Second}
		var payloadStr, signature string
		if *tag != "" {
			payloadStr, signature, err = fetchTagSig(ctx, httpClient, *token, *owner, *repo, *tag)
		} else {
			payloadStr, signature, err = fetchCommitSig(ctx, httpClient, *token, *owner, *repo, *commit)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "fetch from GitHub:", err)
			os.Exit(1)
		}
		// We only need the signature to extract TransparencyLogEntry (offline).
		sigBytes = []byte(signature)
		_ = payloadStr
	default:
		fmt.Fprintln(os.Stderr, "Usage: gitsign-extract-tlog --sig-file <path> | --owner <org> --repo <repo> [--tag <name> | --commit <sha>]")
		flag.PrintDefaults()
		os.Exit(2)
	}

	// Accept PEM or raw DER
	if p, _ := pem.Decode(sigBytes); p != nil {
		sigBytes = p.Bytes
	}

	// Parse CMS ContentInfo and SignedData using public smimesign protocol
	ci, err := cmsproto.ParseContentInfo(sigBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse CMS ContentInfo:", err)
		os.Exit(1)
	}
	sd, err := ci.SignedDataContent()
	if err != nil {
		fmt.Fprintln(os.Stderr, "content is not SignedData:", err)
		os.Exit(1)
	}
	if len(sd.SignerInfos) == 0 {
		fmt.Fprintln(os.Stderr, "no signer infos in signature")
		os.Exit(1)
	}
	si := sd.SignerInfos[0]

	// Find the certificate that matches this signer
	certs, err := sd.X509Certificates()
	if err != nil {
		fmt.Fprintln(os.Stderr, "get signature certs:", err)
		os.Exit(1)
	}
	leaf, err := si.FindCertificate(certs)
	if leaf == nil {
		if err != nil {
			fmt.Fprintln(os.Stderr, "find signer certificate:", err)
		}
		fmt.Fprintln(os.Stderr, "no signer certificate found in signature")
		os.Exit(1)
	}

	// Extract SignedAttrs bytes and UnsignedAttrs; reconstruct a LogEntry
	msg, err := si.SignedAttrs.MarshaledForVerification()
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal SignedAttrs:", err)
		os.Exit(1)
	}

	// 1) Unmarshal embedded Rekor TransparencyLogEntry from UnsignedAttrs
	var embedded []byte
	{
		// OID 1.3.6.1.4.1.57264.3.1
		rekorOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 3, 1}
		raw, err := si.UnsignedAttrs.GetOnlyAttributeValueBytes(rekorOID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "extract TransparencyLogEntry attribute:", err)
			os.Exit(1)
		}
		if _, err := asn1.Unmarshal(raw.FullBytes, &embedded); err != nil {
			fmt.Fprintln(os.Stderr, "unmarshal TransparencyLogEntry bytes:", err)
			os.Exit(1)
		}
	}
	pb := new(rekorpb.TransparencyLogEntry)
	if err := proto.Unmarshal(embedded, pb); err != nil {
		fmt.Fprintln(os.Stderr, "decode TransparencyLogEntry proto:", err)
		os.Exit(1)
	}

	// 2) Canonicalize body as hashedrekord using SignedAttrs hash + signer + cert
	sum := sha256.Sum256(msg)
	certPEM, err := cryptoutils.MarshalCertificateToPEM(leaf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal cert to PEM:", err)
		os.Exit(1)
	}
	re := &hashedrekord_v001.V001Entry{
		HashedRekordObj: models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: func() *string { s := "sha256"; return &s }(),
					Value:     func() *string { s := hex.EncodeToString(sum[:]); return &s }(),
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				Content:   strfmt.Base64(si.Signature),
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{Content: strfmt.Base64(certPEM)},
			},
		},
	}
	body, err := types.CanonicalizeEntry(ctx, re)
	if err != nil {
		fmt.Fprintln(os.Stderr, "canonicalize rekor entry body:", err)
		os.Exit(1)
	}

	// 3) Convert proto TransparencyLogEntry -> models.LogEntryAnon (public type)
	le := &models.LogEntryAnon{
		LogID:          func() *string { s := hex.EncodeToString(pb.GetLogId().GetKeyId()); return &s }(),
		LogIndex:       func() *int64 { v := pb.GetLogIndex(); return &v }(),
		IntegratedTime: func() *int64 { v := pb.GetIntegratedTime(); return &v }(),
		Verification: &models.LogEntryAnonVerification{
			SignedEntryTimestamp: pb.GetInclusionPromise().GetSignedEntryTimestamp(),
			InclusionProof: &models.InclusionProof{
				LogIndex: func() *int64 { v := pb.GetInclusionProof().GetLogIndex(); return &v }(),
				TreeSize: func() *int64 { v := pb.GetInclusionProof().GetTreeSize(); return &v }(),
				RootHash: func() *string { s := hex.EncodeToString(pb.GetInclusionProof().GetRootHash()); return &s }(),
				Checkpoint: func() *string {
					if cp := pb.GetInclusionProof().GetCheckpoint(); cp != nil {
						s := cp.GetEnvelope()
						return &s
					}
					return nil
				}(),
				Hashes: func() []string {
					out := make([]string, 0, len(pb.GetInclusionProof().GetHashes()))
					for _, h := range pb.GetInclusionProof().GetHashes() {
						out = append(out, hex.EncodeToString(h))
					}
					return out
				}(),
			},
		},
		Body: base64.StdEncoding.EncodeToString(body),
	}

	// Print as JSON
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(le); err != nil {
		fmt.Fprintln(os.Stderr, "encode JSON:", err)
		os.Exit(1)
	}
}
