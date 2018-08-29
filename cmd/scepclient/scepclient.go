package main

import (
	"context"
	"crypto/md5"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fullsailor/pkcs7"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/innoq/scep/client"
	"github.com/innoq/scep/scep"
	"github.com/pkg/errors"
)

// version info
var (
	version = "unreleased"
	gitHash = "unknown"
)

type runCfg struct {
	dir                   string
	csrPrivateKeySize     int
	csrPrivateKeyPath     string
	csrPublicKeyPath      string
	csrPath               string
	cmsSignPrivateKeyPath string
	cmsSignPublicKeyPath  string
	caCertPath            string
	cn                    string
	subjectKeyId          string
	org                   string
	ou                    string
	locality              string
	province              string
	country               string
	challenge             string
	serverURL             string
	caMD5                 string
	debug                 bool
	logfmt                string
}

func run(cfg runCfg) error {
	ctx := context.Background()
	var logger log.Logger
	{
		if strings.ToLower(cfg.logfmt) == "json" {
			logger = log.NewJSONLogger(os.Stderr)
		} else {
			logger = log.NewLogfmtLogger(os.Stderr)
		}
		stdlog.SetOutput(log.NewStdlibAdapter(logger))
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		if !cfg.debug {
			logger = level.NewFilter(logger, level.AllowInfo())
		}
	}
	lginfo := level.Info(logger)

	client, err := scepclient.New(cfg.serverURL, logger)
	if err != nil {
		return err
	}

	sigAlgo := x509.SHA1WithRSA
	if client.Supports("SHA-256") || client.Supports("SCEPStandard") {
		sigAlgo = x509.SHA256WithRSA
	}

	csrPrivateKey, err := loadOrMakeKey(cfg.csrPrivateKeyPath, cfg.csrPrivateKeySize)
	if err != nil {
		return err
	}

	csrPublicKey, _ := loadPEMCertFromFile(cfg.csrPublicKeyPath)

	logger.Log("info", "")
	opts := &csrOptions{
		cn:         cfg.cn,
		org:        cfg.org,
		country:    strings.ToUpper(cfg.country),
		ou:         cfg.ou,
		locality:   cfg.locality,
		province:   cfg.province,
		challenge:  cfg.challenge,
		privateKey: csrPrivateKey,
		sigAlgo:    sigAlgo,
	}

	csr, err := loadOrMakeCSR(cfg.csrPath, opts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	cmsSignPrivateKey, err := loadOrMakeKey(cfg.cmsSignPrivateKeyPath, cfg.csrPrivateKeySize)
	cmsSignPublicKey, err := loadOrSign(cfg.cmsSignPublicKeyPath, cmsSignPrivateKey, csr, cfg.subjectKeyId)

	var resp []byte
	var certs []*x509.Certificate
	{
		if cfg.caCertPath == "" {
			resp, certNum, err := client.GetCACert(ctx)
			logger.Log("info", fmt.Sprintf("The cacert resp: %v, %v", resp[0:5], certNum))
			if err != nil {
				return err
			}

			certs, err = scep.CACerts(resp)
			if err != nil {
				return err
			}
			if len(certs) == 0 {
				return fmt.Errorf("no certificates returned")
			}
		} else {
			resp, err = ioutil.ReadFile(cfg.caCertPath)
			if err != nil {
				return err
			}
			certs, err = loadCerts(resp)
		}

	}



	var msgType scep.MessageType
	{
		// TODO validate CA and set UpdateReq if needed
		if csrPublicKey != nil {
			msgType = scep.RenewalReq
		} else {
			msgType = scep.PKCSReq
		}
	}

	var recipients []*x509.Certificate
	if cfg.caMD5 == "" {
		recipients = certs
	} else {
		r, err := findRecipients(cfg.caMD5, certs)
		if err != nil {
			return err
		}
		recipients = r
	}

	var algo int
	if client.Supports("AES") || client.Supports("SCEPStandard") {
		algo = pkcs7.EncryptionAlgorithmAES128GCM
	}

	tmpl := &scep.PKIMessage{
		MessageType:             msgType,
		Recipients:              recipients,
		SignerKey:               cmsSignPrivateKey,
		SignerCert:              cmsSignPublicKey,
		SCEPEncryptionAlgorithm: algo,
	}

	if cfg.challenge != "" && msgType == scep.PKCSReq {
		tmpl.CSRReqMessage = &scep.CSRReqMessage{
			ChallengePassword: cfg.challenge,
		}
	}

	msg, err := scep.NewCSRRequest(csr, tmpl, scep.WithLogger(logger))
	if err != nil {
		return errors.Wrap(err, "creating csr pkiMessage")
	}

	var respMsg *scep.PKIMessage

	for {
		// loop in case we get a PENDING response which requires
		// a manual approval.

		respBytes, err := client.PKIOperation(ctx, msg.Raw)
		if err != nil {
			return errors.Wrapf(err, "PKIOperation for %s", msgType)
		}

		respMsg, err = scep.ParsePKIMessage(respBytes, scep.WithLogger(logger))
		if err != nil {
			return errors.Wrapf(err, "parsing pkiMessage response %s", msgType)
		}

		switch respMsg.PKIStatus {
		case scep.FAILURE:
			return errors.Errorf("%s request failed, failInfo: %s", msgType, respMsg.FailInfo)
		case scep.PENDING:
			lginfo.Log("pkiStatus", "PENDING", "msg", "sleeping for 30 seconds, then trying again.")
			time.Sleep(30 * time.Second)
			continue
		}
		lginfo.Log("pkiStatus", "SUCCESS", "msg", "server returned a certificate.")
		break // on scep.SUCCESS
	}

	if err := respMsg.DecryptPKIEnvelope(cmsSignPublicKey, cmsSignPrivateKey); err != nil {
		return errors.Wrapf(err, "decrypt pkiEnvelope, msgType: %s, status %s", msgType, respMsg.PKIStatus)
	}

	respCert := respMsg.CertRepMessage.Certificate
	if err := ioutil.WriteFile(cfg.csrPublicKeyPath, pemCert(respCert.Raw), 0666); err != nil {
		return err
	}

	return nil
}

// Determine the correct recipient based on the fingerprint.
// In case of NDES that is the last certificate in the chain, not the RA cert.
// Return a full chain starting with the cert that matches the fingerprint.
func findRecipients(fingerprint string, certs []*x509.Certificate) ([]*x509.Certificate, error) {
	fingerprint = strings.Join(strings.Split(fingerprint, " "), "")
	fingerprint = strings.ToLower(fingerprint)
	for i, cert := range certs {
		sum := fmt.Sprintf("%x", md5.Sum(cert.Raw))
		if sum == fingerprint {
			return certs[i-1:], nil
		}
	}
	return nil, errors.Errorf("could not find cert for md5 %s", fingerprint)
}

func validateFlags(csrPrivateKeyPath, serverURL string) error {
	if csrPrivateKeyPath == "" {
		return errors.New("must specify csr-privateKey path")
	}
	if serverURL == "" {
		return errors.New("must specify server-url flag parameter")
	}
	_, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("invalid server-url flag parameter %s", err)
	}
	return nil
}

func main() {
	var (
		flVersion               = flag.Bool("version", false, "prints version information")
		flServerURL             = flag.String("server-url", "", "SCEP server url")
		flCsrPrivateKeySize     = flag.Int("csr-privateKey-size", 2048, "rsa privateKey size")
		flCsrPrivateKeyPath     = flag.String("csr-privateKey", "", "client-privateKey output path, if there is no privateKey, scepclient will create one.")
		flCsrPublicKeyPath      = flag.String("csr-publicKey", "", "client-publicKey (the client certificate) output path.")
		flCmsSignPublicKeyPath  = flag.String("cms-sign-publicKey", "", " privateKey path for the cms-signatur, if there is no privateKey, scepclient will create one")
		flCmsSignPrivateKeyPath = flag.String("cms-sign-privateKey", "", "publicKey path for the cms-signatur, if there is no publicKey, scepclient will create one")
		flCaCertPath            = flag.String("ca-cert", "", "ca-cert path, if there is no ca-cert, scepclient will collect the ca-cert from the scep-server")
		flChallengePassword     = flag.String("challenge", "", "enforce a challenge password")
		flCName                 = flag.String("cn", "", "common name for certificate")
		flOrg                   = flag.String("organization", "", "organization for cert")
		flSubjectKeyId          = flag.String("subjectKeyId", "123456789abcdef", "subjectKeyId for the cms certificate")
		flLoc                   = flag.String("locality", "", "locality for certificate")
		flProvince              = flag.String("province", "", "province for certificate")
		flOU                    = flag.String("ou", "", "organizational unit for certificate")
		flCountry               = flag.String("country", "", "country code in certificate")

		// in case of multiple certificate authorities, we need to figure out who the recipient of the encrypted
		// data is.
		flCAFingerprint = flag.String("ca-fingerprint", "", "md5 fingerprint of CA certificate for NDES server.")

		flDebugLogging = flag.Bool("debug", false, "enable debug logging")
		flLogJSON      = flag.Bool("log-json", false, "use JSON for log output")
	)
	flag.Parse()

	// print version information
	if *flVersion {
		fmt.Printf("scepclient - %v\n", version)
		fmt.Printf("git revision - %v\n", gitHash)
		os.Exit(0)
	}

	if err := validateFlags(*flCsrPrivateKeyPath, *flServerURL); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	dir := filepath.Dir(*flCsrPrivateKeyPath)
	csrPath := dir + "/csr.pem"

	if *flCsrPublicKeyPath == "" {
		*flCsrPublicKeyPath = dir + "/client_cert.pem"
	}
	if *flCmsSignPublicKeyPath == "" {
		*flCmsSignPublicKeyPath = dir + "/cms_public_key.pem"
	}
	if *flCmsSignPrivateKeyPath == "" {
		*flCmsSignPrivateKeyPath = dir + "/cms_private_key.pem"
	}
	var logfmt string
	if *flLogJSON {
		logfmt = "json"
	}

	cfg := runCfg{
		dir:                   dir,
		csrPrivateKeySize:     *flCsrPrivateKeySize,
		csrPrivateKeyPath:     *flCsrPrivateKeyPath,
		csrPublicKeyPath:      *flCsrPublicKeyPath,
		cmsSignPrivateKeyPath: *flCmsSignPrivateKeyPath,
		cmsSignPublicKeyPath:  *flCmsSignPublicKeyPath,
		csrPath:               csrPath,
		caCertPath:            *flCaCertPath,
		cn:                    *flCName,
		subjectKeyId:          *flSubjectKeyId,
		org:                   *flOrg,
		country:               *flCountry,
		locality:              *flLoc,
		ou:                    *flOU,
		province:              *flProvince,
		challenge:             *flChallengePassword,
		serverURL:             *flServerURL,
		caMD5:                 *flCAFingerprint,
		debug:                 *flDebugLogging,
		logfmt:                logfmt,
	}

	if err := run(cfg); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
