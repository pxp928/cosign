package attest

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

// AttestBlobCmd implements the logic to attach attestation for a specified blob
func AttestBlobCmd(ctx context.Context, ko options.KeyOpts, artifactPath string, artifactHash string, certPath string,
	certChainPath string, noUpload bool, predicatePath string, predicateType string, timeout time.Duration) error {

	// A key file or token is required unless we're in experimental mode!
	if options.EnableExperimental() {
		if options.NOf(ko.KeyRef, ko.Sk) > 1 {
			return &options.KeyParseError{}
		}
	} else {
		if !options.OneOf(ko.KeyRef, ko.Sk) {
			return &options.KeyParseError{}
		}
	}

	var artifact []byte
	var hexDigest string
	var err error

	if artifactHash == "" {
		if artifactPath == "-" {
			artifact, err = io.ReadAll(os.Stdin)
		} else {
			fmt.Fprintln(os.Stderr, "Using payload from:", artifactPath)
			artifact, err = os.ReadFile(filepath.Clean(artifactPath))
		}
		if err != nil {
			return err
		} else if timeout != 0 {
			var cancelFn context.CancelFunc
			ctx, cancelFn = context.WithTimeout(ctx, timeout)
			defer cancelFn()
		}
	}

	if artifactHash == "" {
		digest, _, err := signature.ComputeDigestForSigning(bytes.NewReader(artifact), crypto.SHA256, []crypto.Hash{crypto.SHA256, crypto.SHA384})
		if err != nil {
			return err
		}
		hexDigest = strings.ToLower(hex.EncodeToString(digest))
	} else {
		hexDigest = artifactHash
	}

	sv, err := sign.SignerFromKeyOpts(ctx, certPath, certChainPath, ko)
	if err != nil {
		return errors.Wrap(err, "getting signer")
	}
	defer sv.Close()
	//pub, err := sv.PublicKey()
	if err != nil {
		return err
	}

	if timeout != 0 {
		var cancelFn context.CancelFunc
		ctx, cancelFn = context.WithTimeout(ctx, timeout)
		defer cancelFn()
	}

	wrapped := dsse.WrapSigner(sv, types.IntotoPayloadType)

	fmt.Fprintln(os.Stderr, "Using payload from:", predicatePath)
	predicate, err := os.Open(predicatePath)
	if err != nil {
		return err
	}
	defer predicate.Close()

	base := path.Base(artifactPath)

	signedPayload, err := getSignedPayload(ctx, wrapped, predicate, predicatePath, predicateType, hexDigest, base)
	if err != nil {
		return errors.Wrap(err, "signing")
	}

	if noUpload {
		fmt.Println(string(signedPayload))
		return nil
	}

	// Check whether we should be uploading to the transparency log
	if options.EnableExperimental() {
		fmt.Println("Uploading to Rekor")
		_, err := attest(ctx, sv, signedPayload, ko.RekorURL)
		if err != nil {
			return err
		}
	}
	return err
}
