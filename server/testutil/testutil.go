package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/agl/ed25519"
	. "github.com/andres-erbsen/dename/client"
	. "github.com/andres-erbsen/dename/protocol"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var INVITE_KEY = []byte("very secret text in the source")

func MakeToken() []byte {
	var r [8]byte
	rand.Read(r[:])
	mac := hmac.New(sha256.New, INVITE_KEY)
	mac.Write(r[:])
	return append(r[:], mac.Sum(nil)[:8]...)
}

type TestingCA struct {
	Rand    io.Reader
	Key     *ecdsa.PrivateKey
	Cert    *x509.Certificate
	CertDER []byte
	Pool    *x509.CertPool
	Config  *tls.Config
}

func newSerial() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}
	return serialNumber
}

func NewTestingCA(rnd io.Reader) (ret *TestingCA, err error) {
	ret = new(TestingCA)
	if rnd == nil {
		rnd = rand.Reader
	}
	ret.Key, err = ecdsa.GenerateKey(elliptic.P224(), rnd)
	if err != nil {
		return nil, err
	}
	ret.Cert = &x509.Certificate{
		Subject:               pkix.Name{CommonName: "TestingCA"},
		SerialNumber:          newSerial(),
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix((1<<31)-1, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:       true,
		MaxPathLen: 4,
	}
	ret.CertDER, err = x509.CreateCertificate(rnd, ret.Cert, ret.Cert, &ret.Key.PublicKey, ret.Key)
	if err != nil {
		return nil, err
	}
	ret.Cert, err = x509.ParseCertificate(ret.CertDER)
	if err != nil {
		return nil, err
	}
	ret.Pool = x509.NewCertPool()
	ret.Pool.AddCert(ret.Cert)
	ret.Config = &tls.Config{RootCAs: ret.Pool}
	ret.Rand = rnd
	return
}

func (tca *TestingCA) NewCertAndKeyToFiles(certfile, keyfile string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P224(), tca.Rand)
	if err != nil {
		return err
	}
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "testingServer"},
		SerialNumber: newSerial(),
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix((1<<31)-1, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, tca.Cert, &priv.PublicKey, tca.Key)
	if err != nil {
		return err
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	certOut, err := os.Create(certfile)
	if err != nil {
		return err
	}
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err != nil {
		return err
	}
	certOut.Close()
	keyOut, err := os.OpenFile(keyfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "127.0.0.1", Roots: tca.Pool}); err != nil {
		return err
	}
	skBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: skBytes})
	if err != nil {
		return err
	}
	keyOut.Close()
	return nil
}

func CreateConfigs(t *testing.T, numCoreServers, numVerifiers, numSubscribers uint) (dirs []string, clientConfig *Config, teardown func()) {
	n := numCoreServers + numVerifiers + numSubscribers
	dir, err := ioutil.TempDir("", "servertest")
	if err != nil {
		t.Fatal(err)
	}
	testingCA, err := NewTestingCA(nil)
	if err != nil {
		panic(err)
	}
	caCertPath := filepath.Join(dir, "ca.crt.pem")
	ioutil.WriteFile(caCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testingCA.CertDER}), os.FileMode(0600))
	ids := make([]uint64, n)
	pks := make(map[uint64]*Profile_PublicKey, n)
	dirMap := make(map[uint64]string, n)
	dirs = make([]string, 0, n)
	configs := make(map[uint64]string, n)
	for i := uint(0); i < n; i++ {
		pkEd, sk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		pk := &Profile_PublicKey{Ed25519: pkEd[:]}
		id := pk.ID()
		ids[i] = id
		pks[id] = pk
		dir := filepath.Join(dir, fmt.Sprintf("%x", id))
		dirs = append(dirs, dir)
		dirMap[id] = dir
		err = os.Mkdir(dir, os.FileMode(0700))
		if err != nil {
			t.Fatal(err)
		}
		ioutil.WriteFile(filepath.Join(dirMap[id], "sk"), sk[:], os.FileMode(0600))
		ioutil.WriteFile(filepath.Join(dirMap[id], "invitekey"), INVITE_KEY, os.FileMode(0600))
		tlsCertPath, tlsKeyPath := filepath.Join(dir, "server.crt.pem"), filepath.Join(dir, "server.key.pem")
		if err := testingCA.NewCertAndKeyToFiles(tlsCertPath, tlsKeyPath); err != nil {
			t.Fatal(err)
		}
		configs[id] = fmt.Sprintf(`[backend]
DataDirectory = %s
SigningKeyPath = %s
Listen = 127.0.0.1:198%d

[frontend]
InviteKeyPath = %s
TLSCertPath = %s
TLSKeyPath = %s
Listen = 127.0.0.1:144%d
`, dir, filepath.Join(dir, "sk"), i, filepath.Join(dir, "invitekey"), tlsCertPath, tlsKeyPath, i)
	}
	for left_i, left_id := range ids {
		putConf := func(i uint) {
			configs[left_id] += fmt.Sprintf(`
[server "127.0.0.1:198%d"]
PublicKey = %s
IsCore = %t
`, i, base64.StdEncoding.EncodeToString(PBEncode(pks[ids[i]])), i < numCoreServers)
		}
		for i := uint(0); i < numCoreServers+numVerifiers; i++ {
			putConf(i)
		}
		if uint(left_i) >= numCoreServers+numVerifiers { // put the server itself in its peers irrespectively of stuff
			putConf(uint(left_i))
		}
		ioutil.WriteFile(filepath.Join(dirMap[left_id], "denameserver.cfg"), []byte(configs[left_id]), os.FileMode(0600))
	}
	cfg := new(Config)
	cfg.Freshness = DefaultFreshness
	cfg.Server = make(map[string]*Server)
	for i, id := range ids {
		cfg.Server[fmt.Sprintf("127.0.0.1:144%d", i)] = &Server{PublicKey: base64.StdEncoding.EncodeToString(PBEncode(pks[id])), TLSCertFile: caCertPath}
	}
	return dirs, cfg, func() {
		os.RemoveAll(dir)
	}
}
