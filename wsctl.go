/**
 * WebSocket Command Line Tool
 * (C) Copyright 2015 Daniel-Constantin Mierla (asipto.com)
 * License: GPLv2
 * 
 */
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"text/template"
	"golang.org/x/net/websocket"
)

var sipTemplates = map[string]string {
    "OPTIONS:TEST": "OPTIONS sip:{{.callee}}@127.0.0.1 SIP/2.0\r\n" +
					"Via: SIP/2.0/WSS df7jal23ls0d.invalid;branch=z9hG4bKasudf-3696-24845-1\r\n" +
					"From: '{{.caller}}' <sip:{{.caller}}@127.0.0.1>;tag=3696-0024845\r\n" +
					"To: '{{.callee}}' <sip:{{.callee}}@127.0.0.1>\r\n" +
					"Call-ID: 24845-3696@127.0.0.1\r\n" +
					"CSeq: 2 OPTIONS\r\n" +
					"Content-Length: 0\r\n\r\n",
}

var templateFields = map[string]map[string]interface{} {
	"FIELDS:EMPTY": { },
	"FIELDS:TEST": { "caller": "alice", "callee": "bob", },
}

type CLIOptions struct {
	wsurl string
	wsorigin string
	wsproto	string
	wsinsecure bool
	wsreceive bool
	wstemplate string
	wsfields string
}

var cliops = CLIOptions{
				wsurl: "wss://127.0.0.1:8443",
				wsorigin: "http://127.0.0.1",
				wsproto: "sip",
				wsinsecure: true,
				wsreceive: true,
				wstemplate: "",
				wsfields: "",
			}


func main() {
    fmt.Printf("starting websocket command line tool (argc: %d)!\n\n", len(os.Args))

    // command line arguments
	flag.Usage = func() {
			fmt.Fprintf(os.Stderr, "Usage of %s (v1.0):\n", filepath.Base(os.Args[0]))
			fmt.Fprintf(os.Stderr, "    (each option has short and long version)\n")
			flag.PrintDefaults()
		}
    flag.StringVar(&cliops.wsfields,   "fields", cliops.wsfields, "name of the internal fields map or path to the json fields file")
    flag.StringVar(&cliops.wsfields,   "f", cliops.wsfields, "name of the internal fields map or path to the json fields file")
    flag.BoolVar(&cliops.wsinsecure,   "insecure", cliops.wsinsecure, "skip tls certificate validation for wss (true|false)")
    flag.BoolVar(&cliops.wsinsecure,   "i", cliops.wsinsecure, "skip tls certificate validation for wss (true|false)")
    flag.StringVar(&cliops.wsorigin,   "origin", cliops.wsorigin, "origin http url")
    flag.StringVar(&cliops.wsorigin,   "o", cliops.wsorigin, "origin http url")
    flag.StringVar(&cliops.wsproto,    "proto", cliops.wsproto, "websocket sub-protocol")
    flag.StringVar(&cliops.wsproto,    "p", cliops.wsproto, "websocket sub-protocol")
    flag.BoolVar(&cliops.wsreceive,    "receive", cliops.wsreceive, "wait to receive response from ws server (true|false)")
    flag.BoolVar(&cliops.wsreceive,    "r", cliops.wsreceive, "wait to receive response from ws server (true|false)")
    flag.StringVar(&cliops.wstemplate, "template", cliops.wstemplate, "name of internal template or path to template file")
    flag.StringVar(&cliops.wstemplate, "t", cliops.wstemplate, "name of internal template or path to template file")
    flag.StringVar(&cliops.wsurl,      "url", cliops.wsurl, "websocket url (ws://... or wss://...)")
    flag.StringVar(&cliops.wsurl,      "u", cliops.wsurl, "websocket url (ws://... or wss://...)")
    flag.Parse()

	// options for ws connections
	urlp, err := url.Parse(cliops.wsurl)
	if err != nil {
		log.Fatal(err)
	}
	orgp, err := url.Parse(cliops.wsorigin)
	if err != nil {
		log.Fatal(err)
	}

	tlc := tls.Config{
			InsecureSkipVerify: false,
		}
	if cliops.wsinsecure {
		tlc.InsecureSkipVerify = true
	}

	// buffer to send over ws connction
	var buf bytes.Buffer
	var tplstr = "";
	if len(cliops.wstemplate) > 0 {
		tpldata, err := ioutil.ReadFile(cliops.wstemplate)
		if err != nil {
			log.Fatal(err)
		}
		tplstr = string(tpldata)
	} else {
		tplstr = sipTemplates["OPTIONS:TEST"]
	}

	var tplfields interface{}
	if len(cliops.wsfields) > 0 {
		fieldsdata, err := ioutil.ReadFile(cliops.wsfields)
		if err != nil {
			log.Fatal(err)
		}
		err = json.Unmarshal(fieldsdata, &tplfields)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		if len(cliops.wstemplate) > 0 {
			tplfields = templateFields["FIELDS:EMPTY"]
		} else {
			tplfields = templateFields["FIELDS:TEST"]
		}
	}

	var tpl = template.Must(template.New("wsout").Parse(tplstr))
	tpl.Execute(&buf, tplfields)
	wmsg := buf.Bytes()

	// open ws connection
	// ws, err := websocket.Dial(wsurl, "", wsorigin)
	ws, err := websocket.DialConfig(&websocket.Config{
						Location: urlp,
						Origin: orgp,
						Protocol: []string{cliops.wsproto},
						Version: 13,
						TlsConfig: &tlc,
						Header: http.Header{"User-Agent": {"wsctl"}},
					})
	if err != nil {
		log.Fatal(err)
	}

	// send data to ws server
	err = ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = ws.Write(wmsg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Sending:\n%s\n", wmsg)

	// receive data from ws server
	if cliops.wsreceive {
		var rmsg = make([]byte, 8192)
		err = ws.SetReadDeadline(time.Now().Add(20 * time.Second))
		_, err = ws.Read(rmsg)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Receiving:\n%s\n", rmsg)
	}
}
