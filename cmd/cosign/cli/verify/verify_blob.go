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
	_ "crypto/sha256" // for `crypto.SHA256`
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	sigs "github.com/sigstore/cosign/pkg/signature"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

func isb64(data []byte) bool {
	_, err := base64.StdEncoding.DecodeString(string(data))
	return err == nil
}

// nolint
func VerifyBlobCmd(ctx context.Context, ko options.KeyOpts, certRef, certEmail,
	certOidcIssuer, certChain, sigRef, blobRef string, enforceSCT bool) error {
	var verifier signature.Verifier
	var cert *x509.Certificate

	if !options.OneOf(ko.KeyRef, ko.Sk, certRef) && !options.EnableExperimental() && ko.BundlePath == "" {
		return &options.PubKeyParseError{}
	}

	sig, b64sig, err := signatures(sigRef, ko.BundlePath)
	if err != nil {
		return err
	}

	blobBytes, err := payloadBytes(blobRef)
	if err != nil {
		return err
	}

	// Keys are optional!
	switch {
	case ko.KeyRef != "":
		verifier, err = sigs.PublicKeyFromKeyRef(ctx, ko.KeyRef)
		if err != nil {
			return errors.Wrap(err, "loading public key")
		}
		pkcs11Key, ok := verifier.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
	case ko.Sk:
		sk, err := pivkey.GetKeyWithSlot(ko.Slot)
		if err != nil {
			return errors.Wrap(err, "opening piv token")
		}
		defer sk.Close()
		verifier, err = sk.Verifier()
		if err != nil {
			return errors.Wrap(err, "loading public key from token")
		}
	case certRef != "":
		cert, err = loadCertFromFileOrURL(certRef)
		if err != nil {
			return err
		}
		co := &cosign.CheckOpts{
			CertEmail:      certEmail,
			CertOidcIssuer: certOidcIssuer,
			EnforceSCT:     enforceSCT,
		}
		if certChain == "" {
			err = cosign.CheckCertificatePolicy(cert, co)
			if err != nil {
				return err
			}
			verifier, err = signature.LoadVerifier(cert.PublicKey, crypto.SHA256)
			if err != nil {
				return err
			}
		} else {
			// Verify certificate with chain
			chain, err := loadCertChainFromFileOrURL(certChain)
			if err != nil {
				return err
			}
			verifier, err = cosign.ValidateAndUnpackCertWithChain(cert, chain, co)
			if err != nil {
				return err
			}
		}
	case ko.BundlePath != "":
		b, err := cosign.FetchLocalSignedPayloadFromPath(ko.BundlePath)
		if err != nil {
			return err
		}
		if b.Cert == "" {
			return fmt.Errorf("bundle does not contain cert for verification, please provide public key")
		}
		// cert can either be a cert or public key
		certBytes := []byte(b.Cert)
		if isb64(certBytes) {
			certBytes, _ = base64.StdEncoding.DecodeString(b.Cert)
		}
		cert, err = loadCertFromPEM(certBytes)
		if err != nil {
			// check if cert is actually a public key
			verifier, err = sigs.LoadPublicKeyRaw(certBytes, crypto.SHA256)
		} else {
			verifier, err = signature.LoadVerifier(cert.PublicKey, crypto.SHA256)
		}
		if err != nil {
			return err
		}
	case options.EnableExperimental():
		rClient, err := rekor.NewClient(ko.RekorURL)
		if err != nil {
			return err
		}

		uuids, err := cosign.FindTLogEntriesByPayload(ctx, rClient, blobBytes)
		if err != nil {
			return err
		}

		if len(uuids) == 0 {
			return errors.New("could not find a tlog entry for provided blob")
		}
		return verifySigByUUID(ctx, ko, rClient, certEmail, certOidcIssuer, sig, b64sig, uuids, blobBytes, enforceSCT)
	}

	// Use the DSSE verifier if the payload is a DSSE with the In-Toto format.
	if isIntotoDSSE(blobBytes) {
		verifier = dsse.WrapVerifier(verifier)
	}

	// verify the signature
	if err := verifier.VerifySignature(bytes.NewReader([]byte(sig)), bytes.NewReader(blobBytes)); err != nil {
		return err
	}

	// verify the rekor entry
	if err := verifyRekorEntry(ctx, ko, nil, verifier, cert, b64sig, blobBytes); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Verified OK")
	return nil
}
