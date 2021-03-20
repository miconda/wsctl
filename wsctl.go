/**
 * WebSocket Command Line Tool
 * (C) Copyright 2015 Daniel-Constantin Mierla (asipto.com)
 * License: GPLv2
 */

package main

import (
	"bytes"
	"crypto/md5"
	cryptorand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	mathrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/websocket"
)

const wsctlVersion = "1.1.0"

var templateDefaultText string = `OPTIONS sip:{{.callee}}@{{.domain}} SIP/2.0
Via: SIP/2.0/WSS df7jal23ls0d.invalid;branch=z9hG4bKasudf-3696-24845-1
From: "{{.caller}}" <sip:{{.caller}}@{{.domain}}>;tag={{.fromtag}}
To: "{{.callee}}" <sip:{{.callee}}@{{.domain}}>
Call-ID: {{.callid}}
CSeq: {{.cseqnum}} OPTIONS
Subject: testing
Date: {{.date}}
Content-Length: 0

`

var templateDefaultJSONFields string = `{
	"caller": "alice",
	"callee": "bob",
	"domain": "localhost",
	"fromtag": "$uuid",
	"callid": "$uuid",
	"cseqnum": "$randseq",
	"date": "$daterfc1123"
}`

var templateFields = map[string]map[string]interface{}{
	"FIELDS:EMPTY": {},
}

type paramFieldsType map[string]string

func (m paramFieldsType) String() string {
	b := new(bytes.Buffer)
	for key, value := range m {
		fmt.Fprintf(b, "%s:%s\n", key, value)
	}
	return b.String()
}

func (m paramFieldsType) Set(value string) error {
	z := strings.SplitN(value, ":", 2)
	if len(z) > 1 {
		m[z[0]] = z[1]
	}
	return nil
}

var paramFields = make(paramFieldsType)

//
// CLIOptions - structure for command line options
type CLIOptions struct {
	wsurl              string
	wsorigin           string
	wsproto            string
	wsinsecure         bool
	wsreceive          bool
	wstemplate         string
	wstemplaterun      bool
	wsfields           string
	wsfieldseval       bool
	wscrlf             bool
	version            bool
	wsauser            string
	wsapasswd          string
	wstimeoutrecv      int
	wstimeoutsend      int
	wsoutputfile       string
	wsuuid             bool
	wsflagdefaults     bool
	wstemplatedefaults bool
	wsdomainurl        bool
	wsdomainorigin     bool
	wshttpdomain       string
	wshttpsrv          string
	wshttpssrv         string
	wshttpspubkey      string
	wshttpsprvkey      string
	wshttpsusele       bool
}

var cliops = CLIOptions{
	wsurl:              "wss://127.0.0.1:8443",
	wsorigin:           "http://127.0.0.1",
	wsproto:            "sip",
	wsinsecure:         true,
	wsreceive:          true,
	wstemplate:         "",
	wstemplaterun:      false,
	wsfields:           "",
	wsfieldseval:       false,
	wscrlf:             false,
	version:            false,
	wsauser:            "",
	wsapasswd:          "",
	wstimeoutrecv:      20000,
	wstimeoutsend:      10000,
	wsoutputfile:       "",
	wsuuid:             false,
	wsflagdefaults:     false,
	wstemplatedefaults: false,
	wsdomainurl:        false,
	wsdomainorigin:     false,
	wshttpdomain:       "",
	wshttpsrv:          "",
	wshttpssrv:         "",
	wshttpspubkey:      "",
	wshttpsprvkey:      "",
	wshttpsusele:       false,
}

//
var outputFile *os.File

//
// initialize application components
func init() {
	// command line arguments
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s (v%s):\n", filepath.Base(os.Args[0]), wsctlVersion)
		fmt.Fprintf(os.Stderr, "    (some options have short and long version)\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	flag.StringVar(&cliops.wsauser, "auser", cliops.wsauser, "username to be used for authentication")
	flag.StringVar(&cliops.wsapasswd, "apasswd", cliops.wsapasswd, "password to be used for authentication")
	flag.BoolVar(&cliops.wscrlf, "crlf", cliops.wscrlf, "replace '\\n' with '\\r\\n' inside the data to be sent (true|false)")
	flag.StringVar(&cliops.wsfields, "fields", cliops.wsfields, "path to the json fields file")
	flag.StringVar(&cliops.wsfields, "f", cliops.wsfields, "path to the json fields file")
	flag.BoolVar(&cliops.wsfieldseval, "fields-eval", cliops.wsfieldseval, "evaluate expression in fields file")
	flag.BoolVar(&cliops.wsinsecure, "insecure", cliops.wsinsecure, "skip tls certificate validation for wss (true|false)")
	flag.BoolVar(&cliops.wsinsecure, "i", cliops.wsinsecure, "skip tls certificate validation for wss (true|false)")
	flag.StringVar(&cliops.wsorigin, "origin", cliops.wsorigin, "origin http url")
	flag.StringVar(&cliops.wsorigin, "o", cliops.wsorigin, "origin http url")
	flag.StringVar(&cliops.wsproto, "proto", cliops.wsproto, "websocket sub-protocol")
	flag.StringVar(&cliops.wsproto, "p", cliops.wsproto, "websocket sub-protocol")
	flag.BoolVar(&cliops.wsreceive, "receive", cliops.wsreceive, "wait to receive response from ws server (true|false)")
	flag.BoolVar(&cliops.wsreceive, "r", cliops.wsreceive, "wait to receive response from ws server (true|false)")
	flag.StringVar(&cliops.wstemplate, "template", cliops.wstemplate, "path to template file")
	flag.StringVar(&cliops.wstemplate, "t", cliops.wstemplate, "path to template file")
	flag.StringVar(&cliops.wsurl, "url", cliops.wsurl, "websocket url (ws://... or wss://...)")
	flag.StringVar(&cliops.wsurl, "u", cliops.wsurl, "websocket url (ws://... or wss://...)")
	flag.BoolVar(&cliops.version, "version", cliops.version, "print version")
	flag.IntVar(&cliops.wstimeoutrecv, "timeout-recv", cliops.wstimeoutrecv, "timeout waiting to receive data (milliseconds)")
	flag.IntVar(&cliops.wstimeoutsend, "timeout-send", cliops.wstimeoutsend, "timeout trying to send data (milliseconds)")
	flag.StringVar(&cliops.wsoutputfile, "output-file", cliops.wsoutputfile, "path to the file where to store sent and received messages")
	flag.StringVar(&cliops.wsoutputfile, "O", cliops.wsoutputfile, "path to the file where to store sent and received messages")
	flag.BoolVar(&cliops.wsuuid, "uuid", cliops.wsuuid, "generate and print a uuid")
	flag.BoolVar(&cliops.wstemplaterun, "template-run", cliops.wstemplaterun, "run template execution and print the result")
	flag.Var(&paramFields, "field-val", "field value in format 'name:value' (can be provided many times)")
	flag.BoolVar(&cliops.wsflagdefaults, "flag-defaults", cliops.wsflagdefaults, "print flag (cli param) default values")
	flag.BoolVar(&cliops.wstemplatedefaults, "template-defaults", cliops.wstemplatedefaults, "print default (internal) template data")
	flag.BoolVar(&cliops.wsdomainurl, "domain-url", cliops.wsdomainurl, "set domain field value extracting from URL parameter")
	flag.BoolVar(&cliops.wsdomainorigin, "domain-origin", cliops.wsdomainorigin, "set domain field value extracting from origin parameter")
	flag.StringVar(&cliops.wshttpdomain, "http-domain", cliops.wshttpdomain, "http service domain")
	flag.StringVar(&cliops.wshttpsrv, "http-srv", cliops.wshttpsrv, "http server bind address")
	flag.StringVar(&cliops.wshttpssrv, "https-srv", cliops.wshttpssrv, "https server bind address")
	flag.StringVar(&cliops.wshttpspubkey, "https-pubkey", cliops.wshttpspubkey, "https server public key")
	flag.StringVar(&cliops.wshttpsprvkey, "https-prvkey", cliops.wshttpsprvkey, "https server private key")
}

// Echo-only service with direct copy
func WSServerEchoOnly(ws *websocket.Conn) {
	fmt.Printf("echo-only - service requested\n")
	io.Copy(ws, ws)
	fmt.Println("echo-only - service finished\n")
}

// Echo service with logging of content
func WSServerEcho(ws *websocket.Conn) {
	fmt.Printf("echo - service requested: %#v\n", ws)
	for {
		var buf string
		err := websocket.Message.Receive(ws, &buf)
		if err != nil {
			fmt.Println(err)
			break
		}
		fmt.Printf("echo - message received: %q\n", buf)
		err = websocket.Message.Send(ws, buf)
		if err != nil {
			fmt.Println(err)
			break
		}
		fmt.Printf("echo - message sent: %q\n", buf)
	}
	fmt.Printf("echo - service finished: %#v\n", ws)
}

// Echo service with logging of content
func WSServerEchoReply(ws *websocket.Conn) {
	fmt.Printf("echo-reply - service requested: %#v\n", ws)
	for {
		var buf string
		err := websocket.Message.Receive(ws, &buf)
		if err != nil {
			fmt.Println(err)
			break
		}
		fmt.Printf("echo-reply - message received: %q\n", buf)
		err = websocket.Message.Send(ws, "Replying-To: "+buf)
		if err != nil {
			fmt.Println(err)
			break
		}
		fmt.Printf("echo-reply - message sent: %q\n", buf)
	}
	fmt.Printf("echo-reply - service finished: %#v\n", ws)
}

// Log service to print received messages
func WSServerLog(ws *websocket.Conn) {
	fmt.Printf("log - service requested: %#v\n", ws)
	for {
		var buf string
		err := websocket.Message.Receive(ws, &buf)
		if err != nil {
			fmt.Println(err)
			break
		}
		fmt.Printf("log - message received: %q\n", buf)
	}
	fmt.Printf("log - service finished: %#v\n", ws)
}

//
// Start http and https services
func startHTTPServices() chan error {

	errchan := make(chan error)

	// starting HTTP server
	if len(cliops.wshttpsrv) > 0 {
		go func() {
			log.Printf("staring HTTP service on: %s ...", cliops.wshttpsrv)

			if err := http.ListenAndServe(cliops.wshttpsrv, nil); err != nil {
				errchan <- err
			}

		}()
	}

	// starting HTTPS server
	if len(cliops.wshttpssrv) > 0 && len(cliops.wshttpspubkey) > 0 && len(cliops.wshttpsprvkey) > 0 {
		go func() {
			log.Printf("Staring HTTPS service on: %s ...", cliops.wshttpssrv)
			if err := http.ListenAndServeTLS(cliops.wshttpssrv, cliops.wshttpspubkey, cliops.wshttpsprvkey, nil); err != nil {
				errchan <- err
			}
		}()
	}

	return errchan
}

//
// wsctl application
func main() {

	flag.Parse()

	fmt.Printf("\n")

	if cliops.version {
		fmt.Printf("%s v%s\n", filepath.Base(os.Args[0]), wsctlVersion)
		os.Exit(1)
	}

	if len(cliops.wshttpsrv) > 0 || len(cliops.wshttpssrv) > 0 {
		if cliops.wshttpsusele && len(cliops.wshttpdomain) == 0 {
			log.Printf("use-letsencrypt requires http domain parameter\n")
			os.Exit(1)
		}
		if cliops.wshttpsusele && len(cliops.wshttpssrv) > 0 && len(cliops.wshttpdomain) > 0 {
			cliops.wshttpspubkey = "/etc/letsencrypt/live/" + cliops.wshttpdomain + "/fullchain.pem"
			cliops.wshttpsprvkey = "/etc/letsencrypt/live/" + cliops.wshttpdomain + "/privkey.pem"
		}
		http.Handle("/echo-only", websocket.Handler(WSServerEchoOnly))
		http.Handle("/echo-reply", websocket.Handler(WSServerEchoReply))
		http.Handle("/echo", websocket.Handler(WSServerEcho))
		http.Handle("/log", websocket.Handler(WSServerLog))
		errchan := startHTTPServices()
		select {
		case err := <-errchan:
			log.Printf("unable to start http services due to (error: %v)", err)
		}
		os.Exit(1)
	}
	if cliops.wstemplatedefaults {
		fmt.Println("Default template:\n")
		fmt.Println(templateDefaultText)
		fmt.Println("Default fields:\n")
		fmt.Println(templateDefaultJSONFields)
		os.Exit(1)
	}
	if cliops.wsflagdefaults {
		flag.PrintDefaults()
		os.Exit(1)
	}
	if cliops.wsuuid {
		uuidVal := uuid.New()
		fmt.Println(uuidVal)
		os.Exit(1)
	}

	// enable file name and line numbers in logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// options for ws connections
	urlp, err := url.Parse(cliops.wsurl)
	if err != nil {
		log.Fatal(err)
	}
	orgp, err := url.Parse(cliops.wsorigin)
	if err != nil {
		log.Fatal(err)
	}

	// buffer to send over ws connection
	var buf bytes.Buffer
	var tplstr = ""
	if len(cliops.wstemplate) > 0 {
		tpldata, err1 := ioutil.ReadFile(cliops.wstemplate)
		if err1 != nil {
			log.Fatal(err1)
		}
		tplstr = string(tpldata)
	} else if len(templateDefaultText) > 0 {
		tplstr = templateDefaultText
	} else {
		log.Fatal("missing data template file ('-t' or '--template' parameter must be provided)")
	}

	tplfields := make(map[string]interface{})
	if len(cliops.wsfields) > 0 {
		fieldsdata, err1 := ioutil.ReadFile(cliops.wsfields)
		if err1 != nil {
			log.Fatal(err1)
		}
		err = json.Unmarshal(fieldsdata, &tplfields)
		if err != nil {
			log.Fatal(err)
		}
	} else if len(templateDefaultJSONFields) > 0 {
		err = json.Unmarshal([]byte(templateDefaultJSONFields), &tplfields)
		if err != nil {
			log.Fatal(err)
		}
		cliops.wsfieldseval = true
	} else {
		tplfields = templateFields["FIELDS:EMPTY"]
	}
	if cliops.wsfieldseval {
		for k := range tplfields {
			switch tplfields[k].(type) {
			case string:
				if tplfields[k] == "$uuid" {
					tplfields[k] = uuid.New().String()
				} else if tplfields[k] == "$randseq" {
					mathrand.Seed(time.Now().Unix())
					tplfields[k] = strconv.Itoa(1 + mathrand.Intn(999999))
				} else if tplfields[k] == "$datefull" {
					tplfields[k] = time.Now().String()
				} else if tplfields[k] == "$daterfc1123" {
					tplfields[k] = time.Now().Format(time.RFC1123)
				} else if tplfields[k] == "$dateunix" {
					tplfields[k] = time.Now().Format(time.UnixDate)
				} else if tplfields[k] == "$dateansic" {
					tplfields[k] = time.Now().Format(time.ANSIC)
				} else if tplfields[k] == "$timestamp" {
					tplfields[k] = strconv.FormatInt(time.Now().Unix(), 10)
				} else if tplfields[k] == "$cr" {
					tplfields[k] = "\r"
				} else if tplfields[k] == "$lf" {
					tplfields[k] = "\n"
				}
				break
			}
		}
	}
	if len(paramFields) > 0 {
		for k := range paramFields {
			tplfields[k] = paramFields[k]
		}
	}
	if cliops.wsdomainurl {
		tplfields["domain"] = urlp.Hostname()
	}
	if cliops.wsdomainorigin {
		tplfields["domain"] = orgp.Hostname()
	}

	var tpl = template.Must(template.New("wsout").Parse(tplstr))
	tpl.Execute(&buf, tplfields)

	var wmsg []byte
	if cliops.wscrlf {
		wmsg = []byte(strings.Replace(buf.String(), "\n", "\r\n", -1))
	} else {
		wmsg = buf.Bytes()
	}

	if cliops.wstemplaterun {
		fmt.Println(string(wmsg))
		os.Exit(1)
	}

	tlc := tls.Config{
		InsecureSkipVerify: false,
	}
	if cliops.wsinsecure {
		tlc.InsecureSkipVerify = true
	}

	if cliops.wsoutputfile != "" {
		outputFile, err = os.Create(cliops.wsoutputfile)
		if err != nil {
			log.Fatal("Cannot create file", err)
		}
		defer outputFile.Close()
	}

	// open ws connection
	// ws, err := websocket.Dial(wsurl, "", wsorigin)
	ws, err := websocket.DialConfig(&websocket.Config{
		Location:  urlp,
		Origin:    orgp,
		Protocol:  []string{cliops.wsproto},
		Version:   13,
		TlsConfig: &tlc,
		Header:    http.Header{"User-Agent": {"wsctl"}},
	})
	if err != nil {
		log.Fatal(err)
	}

	// send data to ws server
	err = ws.SetWriteDeadline(time.Now().Add(time.Duration(cliops.wstimeoutsend) * time.Millisecond))
	if err != nil {
		log.Fatal(err)
	}
	_, err = ws.Write(wmsg)
	if err != nil {
		log.Fatal(err)
	}
	localAddr := ws.LocalAddr()
	remoteAddr := ws.RemoteAddr()
	fmt.Printf("[%s] ** snd (%d bytes)\n    -- %s => %s --\n%s\n", time.Now(), len(wmsg), localAddr.String(), remoteAddr.String(), wmsg)
	if cliops.wsoutputfile != "" {
		fmt.Fprintf(outputFile, "[%s] ** snd (%d bytes)\n    -- %s => %s --\n%s\n\n", time.Now(), len(wmsg), localAddr.String(), remoteAddr.String(), wmsg)
	}

	// receive data from ws server
	if cliops.wsreceive {
		var rmsg = make([]byte, 8192)
		err = ws.SetReadDeadline(time.Now().Add(time.Duration(cliops.wstimeoutrecv) * time.Millisecond))
		if err != nil {
			log.Fatal(err)
		}
		n, err := ws.Read(rmsg)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("[%s] ** rcv (%d bytes)\n    -- %s => %s --\n%s\n", time.Now(), n, remoteAddr.String(), localAddr.String(), rmsg)
		if cliops.wsoutputfile != "" {
			fmt.Fprintf(outputFile, "[%s] ** rcv (%d bytes)\n    -- %s => %s --\n%s\n\n", time.Now(), n, remoteAddr.String(), localAddr.String(), rmsg)
		}
		if n > 24 && cliops.wsproto == "sip" {
			ManageSIPResponse(ws, wmsg, rmsg)
		}
	}
}

//
// ParseAuthHeader - parse www/proxy-authenticate header body.
// Return a map of parameters or nil if the header is not Digest auth header.
func ParseAuthHeader(hbody []byte) map[string]string {
	s := strings.SplitN(strings.Trim(string(hbody), " "), " ", 2)
	if len(s) != 2 || s[0] != "Digest" {
		return nil
	}

	params := map[string]string{}
	for _, kv := range strings.Split(s[1], ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		params[strings.Trim(parts[0], "\" ")] = strings.Trim(parts[1], "\" ")
	}
	return params
}

//
// BuildAuthResponseHeader - return the body for auth header in response
func BuildAuthResponseHeader(username string, password string, hparams map[string]string) string {
	// https://en.wikipedia.org/wiki/Digest_access_authentication
	// HA1
	h := md5.New()
	A1 := fmt.Sprintf("%s:%s:%s", username, hparams["realm"], password)
	io.WriteString(h, A1)
	HA1 := fmt.Sprintf("%x", h.Sum(nil))

	// HA2
	h = md5.New()
	A2 := fmt.Sprintf("%s:%s", hparams["method"], hparams["uri"])
	io.WriteString(h, A2)
	HA2 := fmt.Sprintf("%x", h.Sum(nil))

	var AuthHeader string
	if _, ok := hparams["qop"]; !ok {
		// build digest response
		response := HMD5(strings.Join([]string{HA1, hparams["nonce"], HA2}, ":"))
		// build header body
		AuthHeader = fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm=MD5, response="%s"`,
			username, hparams["realm"], hparams["nonce"], hparams["uri"], response)
	} else {
		// build digest response
		cnonce := RandomKey()
		response := HMD5(strings.Join([]string{HA1, hparams["nonce"], "00000001", cnonce, hparams["qop"], HA2}, ":"))
		// build header body
		AuthHeader = fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", cnonce="%s", nc=00000001, qop=%s, opaque="%s", algorithm=MD5, response="%s"`,
			username, hparams["realm"], hparams["nonce"], hparams["uri"], cnonce, hparams["qop"], hparams["opaque"], response)
	}
	return AuthHeader
}

//
// RandomKey - return random key (used for cnonce)
func RandomKey() string {
	key := make([]byte, 12)
	for b := 0; b < len(key); {
		n, err := cryptorand.Read(key[b:])
		if err != nil {
			panic("failed to get random bytes")
		}
		b += n
	}
	return base64.StdEncoding.EncodeToString(key)
}

//
// HMD5 - return a lower-case hex MD5 digest of the parameter
func HMD5(data string) string {
	md5d := md5.New()
	md5d.Write([]byte(data))
	return fmt.Sprintf("%x", md5d.Sum(nil))
}

//
// ManageSIPResponse - process a SIP response
// - if was a 401/407, follow up with authentication request
func ManageSIPResponse(ws *websocket.Conn, wmsg []byte, rmsg []byte) bool {
	if cliops.wsapasswd == "" {
		return false
	}
	// www or proxy authentication
	hname := ""
	if bytes.HasPrefix(rmsg, []byte("SIP/2.0 401 ")) {
		hname = "WWW-Authenticate:"
	} else if bytes.HasPrefix(rmsg, []byte("SIP/2.0 407 ")) {
		hname = "Proxy-Authenticate:"
	}
	n := bytes.Index(rmsg, []byte(hname))
	if n < 0 {
		return false
	}
	hbody := bytes.Trim(rmsg[n:n+bytes.Index(rmsg[n:], []byte("\n"))], " \t\r")
	hparams := ParseAuthHeader(hbody[len(hname):])
	if hparams == nil {
		return false
	}
	auser := "test"
	if cliops.wsauser != "" {
		auser = cliops.wsauser
	}

	s := strings.SplitN(string(wmsg), " ", 3)
	if len(s) != 3 {
		return false
	}

	hparams["method"] = s[0]
	hparams["uri"] = s[1]
	fmt.Printf("\nAuth params map:\n    %+v\n\n", hparams)
	authResponse := BuildAuthResponseHeader(auser, cliops.wsapasswd, hparams)

	// build new request - increase CSeq and insert auth header
	n = bytes.Index(wmsg, []byte("CSeq:"))
	if n < 0 {
		n = bytes.Index(wmsg, []byte("s:"))
		if n < 0 {
			return false
		}
	}
	hbody = bytes.Trim(wmsg[n:n+bytes.Index(wmsg[n:], []byte("\n"))], " \t\r")
	var obuf bytes.Buffer
	obuf.Write(wmsg[:n])
	s = strings.SplitN(string(hbody), " ", 3)
	if len(s) != 3 {
		return false
	}
	csn, _ := strconv.Atoi(s[1])
	cs := strconv.Itoa(1 + csn)

	obuf.WriteString("CSeq: " + cs + " " + s[2] + "\r\n")
	if hname[0] == 'W' {
		obuf.WriteString("Authorization: ")
	} else {
		obuf.WriteString("Proxy-Authorization: ")
	}
	obuf.WriteString(authResponse)
	obuf.WriteString("\r\n")
	obuf.Write(wmsg[1+n+bytes.Index(wmsg[n:], []byte("\n")):])

	// sending data to ws server
	_, err := ws.Write(obuf.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	localAddr := ws.LocalAddr()
	remoteAddr := ws.RemoteAddr()
	fmt.Printf("[%s] ** snd (%d bytes)\n    -- %s => %s --\n%s\n", time.Now(), obuf.Len(), localAddr.String(), remoteAddr.String(), obuf.Bytes())
	if cliops.wsoutputfile != "" {
		fmt.Fprintf(outputFile, "[%s] ** snd (%d bytes)\n    -- %s => %s --\n%s\n\n", time.Now(), obuf.Len(), localAddr.String(), remoteAddr.String(), obuf.Bytes())
	}

	// receive data from ws server
	if cliops.wsreceive {
		var imsg = make([]byte, 8192)
		n, err := ws.Read(imsg)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("[%s] ** rcv (%d bytes)\n    -- %s => %s --\n%s\n", time.Now(), n, remoteAddr.String(), localAddr.String(), imsg)
		if cliops.wsoutputfile != "" {
			fmt.Fprintf(outputFile, "[%s] ** rcv (%d bytes)\n    -- %s => %s --\n%s\n\n", time.Now(), n, remoteAddr.String(), localAddr.String(), imsg)
		}
	}

	return true
}
