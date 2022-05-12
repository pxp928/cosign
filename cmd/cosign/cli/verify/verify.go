//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/blob"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/pkg/cosign/tuf"
	"github.com/sigstore/cosign/pkg/oci"
	sigs "github.com/sigstore/cosign/pkg/signature"
	ctypes "github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	rekord "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

// VerifyCommand verifies a signature on a supplied container image
// nolint
type VerifyCommand struct {
	options.RegistryOptions
	CheckClaims    bool
	KeyRef         string
	CertRef        string
	CertEmail      string
	CertOidcIssuer string
	CertChain      string
	EnforceSCT     bool
	Sk             bool
	Slot           string
	Output         string
	RekorURL       string
	Attachment     string
	Annotations    sigs.AnnotationsMap
	SignatureRef   string
	HashAlgorithm  crypto.Hash
	LocalImage     bool
}

// Exec runs the verification command
func (c *VerifyCommand) Exec(ctx context.Context, images []string) (err error) {
	if len(images) == 0 {
		return flag.ErrHelp
	}

	switch c.Attachment {
	case "sbom", "":
		break
	default:
		return flag.ErrHelp
	}

	// always default to sha256 if the algorithm hasn't been explicitly set
	if c.HashAlgorithm == 0 {
		c.HashAlgorithm = crypto.SHA256
	}

	if !options.OneOf(c.KeyRef, c.CertRef, c.Sk) && !options.EnableExperimental() {
		return &options.PubKeyParseError{}
	}
	ociremoteOpts, err := c.ClientOpts(ctx)
	if err != nil {
		return errors.Wrap(err, "constructing client options")
	}
	co := &cosign.CheckOpts{
		Annotations:        c.Annotations.Annotations,
		RegistryClientOpts: ociremoteOpts,
		CertEmail:          c.CertEmail,
		CertOidcIssuer:     c.CertOidcIssuer,
		EnforceSCT:         c.EnforceSCT,
		SignatureRef:       c.SignatureRef,
	}
	if c.CheckClaims {
		co.ClaimVerifier = cosign.SimpleClaimVerifier
	}
	if options.EnableExperimental() {
		if c.RekorURL != "" {
			rekorClient, err := rekor.NewClient(c.RekorURL)
			if err != nil {
				return errors.Wrap(err, "creating Rekor client")
			}
			co.RekorClient = rekorClient
		}
		co.RootCerts = fulcio.GetRoots()
		co.IntermediateCerts = fulcio.GetIntermediates()
	}
	keyRef := c.KeyRef
	certRef := c.CertRef

	// Keys are optional!
	var pubKey signature.Verifier
	switch {
	case keyRef != "":
		pubKey, err = sigs.PublicKeyFromKeyRefWithHashAlgo(ctx, keyRef, c.HashAlgorithm)
		if err != nil {
			return errors.Wrap(err, "loading public key")
		}
		pkcs11Key, ok := pubKey.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
	case c.Sk:
		sk, err := pivkey.GetKeyWithSlot(c.Slot)
		if err != nil {
			return errors.Wrap(err, "opening piv token")
		}
		defer sk.Close()
		pubKey, err = sk.Verifier()
		if err != nil {
			return errors.Wrap(err, "initializing piv token verifier")
		}
	case certRef != "":
		cert, err := loadCertFromFileOrURL(c.CertRef)
		if err != nil {
			return err
		}
		if c.CertChain == "" {
			err = cosign.CheckCertificatePolicy(cert, co)
			if err != nil {
				return err
			}
			pubKey, err = signature.LoadVerifier(cert.PublicKey, crypto.SHA256)
			if err != nil {
				return err
			}
		} else {
			// Verify certificate with chain
			chain, err := loadCertChainFromFileOrURL(c.CertChain)
			if err != nil {
				return err
			}
			pubKey, err = cosign.ValidateAndUnpackCertWithChain(cert, chain, co)
			if err != nil {
				return err
			}
		}
	}
	co.SigVerifier = pubKey

	// NB: There are only 2 kinds of verification right now:
	// 1. You gave us the public key explicitly to verify against so co.SigVerifier is non-nil or,
	// 2. We're going to find an x509 certificate on the signature and verify against Fulcio root trust
	// TODO(nsmith5): Refactor this verification logic to pass back _how_ verification
	// was performed so we don't need to use this fragile logic here.
	fulcioVerified := (co.SigVerifier == nil)

	for _, img := range images {
		if c.LocalImage {
			verified, bundleVerified, err := cosign.VerifyLocalImageSignatures(ctx, img, co)
			if err != nil {
				return err
			}
			PrintVerificationHeader(img, co, bundleVerified, fulcioVerified)
			PrintVerification(img, verified, c.Output)
		} else {
			ref, err := name.ParseReference(img)
			if err != nil {
				return errors.Wrap(err, "parsing reference")
			}
			ref, err = sign.GetAttachedImageRef(ref, c.Attachment, ociremoteOpts...)
			if err != nil {
				return errors.Wrapf(err, "resolving attachment type %s for image %s", c.Attachment, img)
			}

			verified, bundleVerified, err := cosign.VerifyImageSignatures(ctx, ref, co)
			if err != nil {
				return err
			}

			PrintVerificationHeader(ref.Name(), co, bundleVerified, fulcioVerified)
			PrintVerification(ref.Name(), verified, c.Output)
		}
	}

	return nil
}

func PrintVerificationHeader(imgRef string, co *cosign.CheckOpts, bundleVerified, fulcioVerified bool) {
	fmt.Fprintf(os.Stderr, "\nVerification for %s --\n", imgRef)
	fmt.Fprintln(os.Stderr, "The following checks were performed on each of these signatures:")
	if co.ClaimVerifier != nil {
		if co.Annotations != nil {
			fmt.Fprintln(os.Stderr, "  - The specified annotations were verified.")
		}
		fmt.Fprintln(os.Stderr, "  - The cosign claims were validated")
	}
	if bundleVerified {
		fmt.Fprintln(os.Stderr, "  - Existence of the claims in the transparency log was verified offline")
	} else if co.RekorClient != nil {
		fmt.Fprintln(os.Stderr, "  - The claims were present in the transparency log")
		fmt.Fprintln(os.Stderr, "  - The signatures were integrated into the transparency log when the certificate was valid")
	}
	if co.SigVerifier != nil {
		fmt.Fprintln(os.Stderr, "  - The signatures were verified against the specified public key")
	}
	if fulcioVerified {
		fmt.Fprintln(os.Stderr, "  - Any certificates were verified against the Fulcio roots.")
	}
}

// PrintVerification logs details about the verification to stdout
func PrintVerification(imgRef string, verified []oci.Signature, output string) {
	switch output {
	case "text":
		for _, sig := range verified {
			if cert, err := sig.Cert(); err == nil && cert != nil {
				fmt.Fprintln(os.Stderr, "Certificate subject: ", sigs.CertSubject(cert))
				if issuerURL := sigs.CertIssuerExtension(cert); issuerURL != "" {
					fmt.Fprintln(os.Stderr, "Certificate issuer URL: ", issuerURL)
				}
			}

			p, err := sig.Payload()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching payload: %v", err)
				return
			}
			fmt.Println(string(p))
		}

	default:
		var outputKeys []payload.SimpleContainerImage
		for _, sig := range verified {
			p, err := sig.Payload()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching payload: %v", err)
				return
			}

			ss := payload.SimpleContainerImage{}
			if err := json.Unmarshal(p, &ss); err != nil {
				fmt.Println("error decoding the payload:", err.Error())
				return
			}

			if cert, err := sig.Cert(); err == nil && cert != nil {
				if ss.Optional == nil {
					ss.Optional = make(map[string]interface{})
				}
				ss.Optional["Subject"] = sigs.CertSubject(cert)
				if issuerURL := sigs.CertIssuerExtension(cert); issuerURL != "" {
					ss.Optional["Issuer"] = issuerURL
				}
			}
			if bundle, err := sig.Bundle(); err == nil && bundle != nil {
				if ss.Optional == nil {
					ss.Optional = make(map[string]interface{})
				}
				ss.Optional["Bundle"] = bundle
			}

			outputKeys = append(outputKeys, ss)
		}

		b, err := json.Marshal(outputKeys)
		if err != nil {
			fmt.Println("error when generating the output:", err.Error())
			return
		}

		fmt.Printf("\n%s\n", string(b))
	}
}

func loadCertFromFileOrURL(path string) (*x509.Certificate, error) {
	pems, err := blob.LoadFileOrURL(path)
	if err != nil {
		return nil, err
	}
	return loadCertFromPEM(pems)
}

func loadCertFromPEM(pems []byte) (*x509.Certificate, error) {
	var out []byte
	out, err := base64.StdEncoding.DecodeString(string(pems))
	if err != nil {
		// not a base64
		out = pems
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(out)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("no certs found in pem file")
	}
	return certs[0], nil
}

func loadCertChainFromFileOrURL(path string) ([]*x509.Certificate, error) {
	pems, err := blob.LoadFileOrURL(path)
	if err != nil {
		return nil, err
	}
	certs, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(pems))
	if err != nil {
		return nil, err
	}
	return certs, nil
}

func verifyAttestionByUUID(ctx context.Context, ko options.KeyOpts, rClient *client.Rekor, certEmail, certOidcIssuer, sig, b64sig string,
	uuids []string, blobBytes []byte, enforceSCT bool, verifier signature.Verifier) error {
	var validSigExists bool

	rekorClient, err := rekor.NewClient(ko.RekorURL)
	if err != nil {
		return err
	}

	for _, u := range uuids {
		tlogEntry, err := cosign.GetTlogEntry(ctx, rClient, u)
		if err != nil {
			continue
		}

		if tlogEntry.Attestation == nil {
			continue
		}

		if err := cosign.VerifyTLogEntry(ctx, rekorClient, tlogEntry); err != nil {
			continue
		}

		uuid, err := cosign.ComputeLeafHash(tlogEntry)
		if err != nil {
			continue
		}

		fmt.Fprintf(os.Stderr, "tlog entry verified with uuid: %s index: %d\n", hex.EncodeToString(uuid), *tlogEntry.Verification.InclusionProof.LogIndex)
		validSigExists = true
	}
	if !validSigExists {
		fmt.Fprintln(os.Stderr, `WARNING: No valid entries were found in rekor to verify this blob.

Transparency log support for blobs is experimental, and occasionally an entry isn't found even if one exists.

We recommend requesting the certificate/signature from the original signer of this blob and manually verifying with cosign verify-blob --cert [cert] --signature [signature].`)
		return fmt.Errorf("could not find a valid tlog entry for provided blob, found %d invalid entries", len(uuids))
	}
	fmt.Fprintln(os.Stderr, "Verified OK")
	return nil
}

func verifySigByUUID(ctx context.Context, ko options.KeyOpts, rClient *client.Rekor, certEmail, certOidcIssuer, sig, b64sig string,
	uuids []string, blobBytes []byte, enforceSCT bool) error {
	var validSigExists bool
	for _, u := range uuids {
		tlogEntry, err := cosign.GetTlogEntry(ctx, rClient, u)
		if err != nil {
			continue
		}

		certs, err := extractCerts(tlogEntry)
		if err != nil {
			continue
		}

		co := &cosign.CheckOpts{
			RootCerts:         fulcio.GetRoots(),
			IntermediateCerts: fulcio.GetIntermediates(),
			CertEmail:         certEmail,
			CertOidcIssuer:    certOidcIssuer,
			EnforceSCT:        enforceSCT,
		}
		cert := certs[0]
		verifier, err := cosign.ValidateAndUnpackCert(cert, co)
		if err != nil {
			continue
		}
		// Use the DSSE verifier if the payload is a DSSE with the In-Toto format.
		if isIntotoDSSE(blobBytes) {
			verifier = dsse.WrapVerifier(verifier)
		}
		// verify the signature
		if err := verifier.VerifySignature(bytes.NewReader([]byte(sig)), bytes.NewReader(blobBytes)); err != nil {
			continue
		}

		// verify the rekor entry
		if err := verifyRekorEntry(ctx, ko, tlogEntry, verifier, cert, b64sig, blobBytes); err != nil {
			continue
		}
		validSigExists = true
	}
	if !validSigExists {
		fmt.Fprintln(os.Stderr, `WARNING: No valid entries were found in rekor to verify this blob.

Transparency log support for blobs is experimental, and occasionally an entry isn't found even if one exists.

We recommend requesting the certificate/signature from the original signer of this blob and manually verifying with cosign verify-blob --cert [cert] --signature [signature].`)
		return fmt.Errorf("could not find a valid tlog entry for provided blob, found %d invalid entries", len(uuids))
	}
	fmt.Fprintln(os.Stderr, "Verified OK")
	return nil
}

// signatures returns the raw signature and the base64 encoded signature
func signatures(sigRef string, bundlePath string) (string, string, error) {
	var targetSig []byte
	var err error
	switch {
	case sigRef != "":
		targetSig, err = blob.LoadFileOrURL(sigRef)
		if err != nil {
			if !os.IsNotExist(err) {
				// ignore if file does not exist, it can be a base64 encoded string as well
				return "", "", err
			}
			targetSig = []byte(sigRef)
		}
	case bundlePath != "":
		b, err := cosign.FetchLocalSignedPayloadFromPath(bundlePath)
		if err != nil {
			return "", "", err
		}
		targetSig = []byte(b.Base64Signature)
	default:
		return "", "", fmt.Errorf("missing flag '--signature'")
	}

	var sig, b64sig string
	if isb64(targetSig) {
		b64sig = string(targetSig)
		sigBytes, _ := base64.StdEncoding.DecodeString(b64sig)
		sig = string(sigBytes)
	} else {
		sig = string(targetSig)
		b64sig = base64.StdEncoding.EncodeToString(targetSig)
	}
	return sig, b64sig, nil
}

func payloadBytes(blobRef string) ([]byte, error) {
	var blobBytes []byte
	var err error
	if blobRef == "-" {
		blobBytes, err = io.ReadAll(os.Stdin)
	} else {
		blobBytes, err = blob.LoadFileOrURL(blobRef)
	}
	if err != nil {
		return nil, err
	}
	return blobBytes, nil
}

func verifyRekorEntry(ctx context.Context, ko options.KeyOpts, e *models.LogEntryAnon, pubKey signature.Verifier, cert *x509.Certificate, b64sig string, blobBytes []byte) error {
	// If we have a bundle with a rekor entry, let's first try to verify offline
	if ko.BundlePath != "" {
		if err := verifyRekorBundle(ctx, ko.BundlePath, cert); err == nil {
			fmt.Fprintf(os.Stderr, "tlog entry verified offline\n")
			return nil
		}
	}
	if !options.EnableExperimental() {
		return nil
	}

	rekorClient, err := rekor.NewClient(ko.RekorURL)
	if err != nil {
		return err
	}
	// Only fetch from rekor tlog if we don't already have the entry.
	if e == nil {
		var pubBytes []byte
		if pubKey != nil {
			pubBytes, err = sigs.PublicKeyPem(pubKey, signatureoptions.WithContext(ctx))
			if err != nil {
				return err
			}
		}
		if cert != nil {
			pubBytes, err = cryptoutils.MarshalCertificateToPEM(cert)
			if err != nil {
				return err
			}
		}
		e, err = cosign.FindTlogEntry(ctx, rekorClient, b64sig, blobBytes, pubBytes)
		if err != nil {
			return err
		}
	}

	if err := cosign.VerifyTLogEntry(ctx, rekorClient, e); err != nil {
		return nil
	}

	uuid, err := cosign.ComputeLeafHash(e)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "tlog entry verified with uuid: %s index: %d\n", hex.EncodeToString(uuid), *e.Verification.InclusionProof.LogIndex)
	if cert == nil {
		return nil
	}
	// if we have a cert, we should check expiry
	return cosign.CheckExpiry(cert, time.Unix(*e.IntegratedTime, 0))
}

func verifyRekorBundle(ctx context.Context, bundlePath string, cert *x509.Certificate) error {
	b, err := cosign.FetchLocalSignedPayloadFromPath(bundlePath)
	if err != nil {
		return err
	}
	if b.Bundle == nil {
		return fmt.Errorf("rekor entry is not available")
	}
	publicKeys, err := cosign.GetRekorPubs(ctx)
	if err != nil {
		return errors.Wrap(err, "retrieving rekor public key")
	}

	pubKey, ok := publicKeys[b.Bundle.Payload.LogID]
	if !ok {
		return errors.New("rekor log public key not found for payload")
	}
	err = cosign.VerifySET(b.Bundle.Payload, b.Bundle.SignedEntryTimestamp, pubKey.PubKey)
	if err != nil {
		return err
	}
	if pubKey.Status != tuf.Active {
		fmt.Fprintf(os.Stderr, "**Info** Successfully verified Rekor entry using an expired verification key\n")
	}

	if cert == nil {
		return nil
	}
	it := time.Unix(b.Bundle.Payload.IntegratedTime, 0)
	return cosign.CheckExpiry(cert, it)
}

func extractCerts(e *models.LogEntryAnon) ([]*x509.Certificate, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	eimpl, err := types.NewEntry(pe)
	if err != nil {
		return nil, err
	}

	var publicKeyB64 []byte
	switch e := eimpl.(type) {
	case *rekord.V001Entry:
		publicKeyB64, err = e.RekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	case *hashedrekord.V001Entry:
		publicKeyB64, err = e.HashedRekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unexpected tlog entry type")
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyB64))
	if err != nil {
		return nil, err
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(publicKey)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, errors.New("no certs found in pem tlog")
	}

	return certs, err
}

// isIntotoDSSE checks whether a payload is a Dead Simple Signing Envelope with the In-Toto format.
func isIntotoDSSE(blobBytes []byte) bool {
	DSSEenvelope := ssldsse.Envelope{}
	if err := json.Unmarshal(blobBytes, &DSSEenvelope); err != nil {
		return false
	}
	if DSSEenvelope.PayloadType != ctypes.IntotoPayloadType {
		return false
	}

	return true
}
