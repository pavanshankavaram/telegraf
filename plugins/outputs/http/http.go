package http

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k8s.io/client-go/rest"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/internal"
	"github.com/influxdata/telegraf/internal/tls"
	"github.com/influxdata/telegraf/plugins/outputs"
	"github.com/influxdata/telegraf/plugins/serializers"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	defaultURL = "http://127.0.0.1:8080/telegraf"
)

var sampleConfig = `
  ## URL is the address to send metrics to
  url = "http://127.0.0.1:8080/telegraf"

  ## Timeout for HTTP message
  # timeout = "5s"

  ## HTTP method, one of: "POST" or "PUT"
  # method = "POST"

  ## HTTP Basic Auth credentials
  # username = "username"
  # password = "pa$$word"

  ## OAuth2 Client Credentials Grant
  # client_id = "clientid"
  # client_secret = "secret"
  # token_url = "https://indentityprovider/oauth2/v1/token"
  # scopes = ["urn:opc:idm:__myscopes__"]

  ## Optional TLS Config
  # tls_ca = "/etc/telegraf/ca.pem"
  # tls_cert = "/etc/telegraf/cert.pem"
  # tls_key = "/etc/telegraf/key.pem"
  ## Use TLS but skip chain & host verification
  # insecure_skip_verify = false

  ## Data format to output.
  ## Each data format has it's own unique set of configuration options, read
  ## more about them here:
  ## https://github.com/influxdata/telegraf/blob/master/docs/DATA_FORMATS_OUTPUT.md
  # data_format = "influx"

  ## HTTP Content-Encoding for write request body, can be set to "gzip" to
  ## compress body or "identity" to apply no encoding.
  # content_encoding = "identity"

  ## Additional HTTP headers
  # [outputs.http.headers]
  #   # Should be set manually to "application/json" for json data_format
  #   Content-Type = "text/plain; charset=utf-8"
`

const (
	defaultClientTimeout = 5 * time.Second
	defaultContentType   = "text/plain; charset=utf-8"
	defaultMethod        = http.MethodPost
)

var (
	wellKnownAzureArcManagementNamespace                       = "azure-arc"
	wellKnownKubernetesSecret                                  = "azure-arc-connect-privatekey"
	k8ClientSet                          *kubernetes.Clientset = nil
	privateKey                           *rsa.PrivateKey
)

type HTTP struct {
	URL             string            `toml:"url"`
	Timeout         internal.Duration `toml:"timeout"`
	Method          string            `toml:"method"`
	Username        string            `toml:"username"`
	Password        string            `toml:"password"`
	Headers         map[string]string `toml:"headers"`
	ClientID        string            `toml:"client_id"`
	ClientSecret    string            `toml:"client_secret"`
	TokenURL        string            `toml:"token_url"`
	Scopes          []string          `toml:"scopes"`
	ContentEncoding string            `toml:"content_encoding"`
	tls.ClientConfig

	client     *http.Client
	serializer serializers.Serializer
}

func (h *HTTP) SetSerializer(serializer serializers.Serializer) {
	h.serializer = serializer
}

func (h *HTTP) createClient(ctx context.Context) (*http.Client, error) {
	tlsCfg, err := h.ClientConfig.TLSConfig()
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
			Proxy:           http.ProxyFromEnvironment,
		},
		Timeout: h.Timeout.Duration,
	}
	if h.ClientID != "" && h.ClientSecret != "" {
		oauthConfig := clientcredentials.Config{
			ClientID:     h.ClientID,
			ClientSecret: h.ClientSecret,
			Scopes:       h.Scopes,
		}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
		client = oauthConfig.Client(ctx)
	}
	return client, nil
}

func (h *HTTP) Connect() error {
	if h.Method == "" {
		h.Method = http.MethodPost
	}
	h.Method = strings.ToUpper(h.Method)
	if h.Method != http.MethodPost && h.Method != http.MethodPut {
		return fmt.Errorf("invalid method [%s] %s", h.URL, h.Method)
	}

	if h.Timeout.Duration == 0 {
		h.Timeout.Duration = defaultClientTimeout
	}

	ctx := context.Background()
	client, err := h.createClient(ctx)
	if err != nil {
		return err
	}

	h.client = client

	return nil
}

func (h *HTTP) Close() error {
	return nil
}

func (h *HTTP) Description() string {
	return "A plugin that can transmit metrics over HTTP"
}

func (h *HTTP) SampleConfig() string {
	return sampleConfig
}

func (h *HTTP) Write(metrics []telegraf.Metric) error {
	reqBody, err := h.serializer.SerializeBatch(metrics)
	if err != nil {
		return err
	}
	if err := h.write(reqBody); err != nil {
		return err
	}

	return nil
}

func (h *HTTP) write(reqBody []byte) error {
	var reqBodyBuffer io.Reader = bytes.NewBuffer(reqBody)

	var err error
	if h.ContentEncoding == "gzip" {
		rc, err := internal.CompressWithGzip(reqBodyBuffer)
		if err != nil {
			return err
		}
		defer rc.Close()
		reqBodyBuffer = rc
	}

	req, err := http.NewRequest(h.Method, h.URL, reqBodyBuffer)
	if err != nil {
		return err
	}

	if h.Username != "" || h.Password != "" {
		req.SetBasicAuth(h.Username, h.Password)
	}

	req.Header.Set("User-Agent", "Telegraf/"+internal.Version())
	req.Header.Set("Content-Type", defaultContentType)
	if h.ContentEncoding == "gzip" {
		req.Header.Set("Content-Encoding", "gzip")
	}
	for k, v := range h.Headers {
		if strings.ToLower(k) == "host" {
			req.Host = v
		}
		req.Header.Set(k, v)
	}
	log.Printf("Signature URL : %s", h.TokenURL)
	_, signedMessage, err := getSharedKey(h.TokenURL)
	req.Header.Set("Authorization", fmt.Sprintf("SharedKey %s", signedMessage))

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("when writing to [%s] received status code: %d", h.URL, resp.StatusCode)
	}

	return nil
}

func getSharedKey(tokenURL string) (string, string, error) {
	// sha256 the message
	log.Printf("token : %s", tokenURL)
	hashed := sha256.Sum256([]byte(tokenURL))
	log.Printf("privateKey : %s", privateKey)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return tokenURL, "", err
	}
	encodedSignature := base64.StdEncoding.EncodeToString([]byte(signature))
	log.Printf("signature : %s", encodedSignature)
	return tokenURL, encodedSignature, nil
}

func getK8ClientSet() (*kubernetes.Clientset, error) {
	if k8ClientSet != nil {
		return k8ClientSet, nil
	}
	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	k8ClientSet = clientset
	return k8ClientSet, nil
}

// GetSecret fetches secret.
func GetSecret(wellKnownKubernetesSecret string) (*rsa.PrivateKey, error) {
	clientset, err := getK8ClientSet()
	if err != nil {
		return nil, err
	}

	secret, err := clientset.CoreV1().Secrets(wellKnownAzureArcManagementNamespace).Get(wellKnownKubernetesSecret, metav1.GetOptions{})
	if err != nil {
		return nil, errors.New("Secret:" + wellKnownKubernetesSecret + " does not exists")
	}
	privateKeyInBytes := string(secret.Data["privateKey"])
	privateKey, err := ParseRsaPrivateKeyFromPemStr([]byte(privateKeyInBytes))
	if err != nil {
		log.Printf("Parsing the Private Key failed : error {%v} ; secret's {name, namespace} Key : {%v}", err, privateKey)
		return nil, err
	}
	return privateKey, err
}

// ParseRsaPrivateKeyFromPemStr gets rsa private key
func ParseRsaPrivateKeyFromPemStr(privPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func init() {
	outputs.Add("http", func() telegraf.Output {
		return &HTTP{
			Timeout: internal.Duration{Duration: defaultClientTimeout},
			Method:  defaultMethod,
			URL:     defaultURL,
		}
	})
	secret, err := GetSecret(wellKnownKubernetesSecret)
	if err != nil {
		
	}
	log.Println("Secret : ", secret)
	privateKey = secret
}
