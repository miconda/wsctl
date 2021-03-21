# wsctl #
WebSocket Command Line Tool

License: `GPLv2`

Copyright: Daniel-Constantin Mierla (Asipto, https://www.asipto.com)

## Overview ##

**wsctl** is a websocket client and basic server to be used from command line. It is written in Go (Golang).

While the common use case for websocket connections is between web browser and web server, there are situations where is more convenient to use a command line (e.g., testing, monitoring).

**wsctl** can send data loaded from a template file to a websocket server and it will print the response received from the server.

It was developed and tested for sending SIP requests over websocket to Kamailio SIP Server (http://www.kamailio.org), but the data can be any format.

For SIP over websocket, it can do www-digest authentication if the server challenges with a 401/407 response.

As a webserver socket, **wsctl** offers a few basic services useful for testing, matching on URL path:

  * `/echo` - copy received message back to the websocket connection and write a log with the message
  * `/echo-only` - only copy what is received back to the websocket connection
  * `/echo-reply` - prefix with `Replying-To: `  what is received and send back to the websocket connection
  * `/log` - write a log with the message received on websocket connection

## Install ##

First install Go (http://golang.org). Once the Go environment is configured, the websocket package must be fetched locally:

```
go get -v golang.org/x/net/websocket
```

Fetch this repository into your Go environment:

```
go get -v -u github.com/miconda/wsctl
```

### Run ##

Navigate to the project folder and run:

```
go run wsctl.go [options]
```

Or install the application:

```
go install github.com/miconda/wsctl
```

And then execute:

```
$GOPATH/bin/wsctl [options]
```

## Command Line Options ##

If run with option `-h` or `--help`, it will print the help message.

The parameter `--template` (short form `-t`) is used to provide the path to template file.
If it is not provided, `wsctl` uses an internal template and fields data, which
build an SIP OPTIONS requests. More details about template files are provided in the next section.

The parameter '--url' can be used to set the URL to websocket server, if not provided, its value is 'wss://127.0.0.1:8443'.

Next is an example of running wsctl by using external template and fields files, to send data to a particular WS server over secure connection:

```
go run wsctl.go \
   --url='wss://myserver.com:8443/ws' \
   --template=examples/options-aa-tpl.sip \
   --fields=examples/options-aa-fld.json
```

To provide username and password for www-digest authentication of SIP requests:

```
go run wsctl.go \
   --url='wss://myserver.com:8443/ws' \
   --template=examples/options-aa-tpl.sip \
   --fields=examples/options-aa-fld.json \
   --auser='test' --apasswd='secret'
```

For websocket secure connections (wss), by default it skips server's TLS certificate verification. To enforce certificate verification add the command line option `--insecure=false`.

The HTTP URL for Origin header can be set with option `--origin=...`. Its default value is `http://127.0.0.1`.

The websocket subprotocol can be set with option `--protocol=...`. Default is `sip`.

## Data Templates ##

The data to be sent via the websocket connection is built from a template file and a fields file.

The template file can contain any any of the directives supported by Go package `text/template` - for more see:

  * https://golang.org/pkg/text/template/

Example:

```
OPTIONS sip:{{.callee}}@{{.domain}} SIP/2.0
Via: SIP/2.0/WSS df7jal23ls0d.invalid;branch=z9hG4bKasudf-3696-24845-1
From: "{{.caller}}" <sip:{{.caller}}@{{.domain}}>;tag={{.fromtag}}
To: "{{.callee}}" <sip:{{.callee}}@{{.domain}}>
Call-ID: {{.callid}}
CSeq: {{.cseqnum}} OPTIONS
Subject: testing
Content-Length: 0

```

The internal template can be found at the top of `wsctl.go` file.

## Data Fields ##

The fields file has to contain a JSON document with the fields to be replaced
in the template file. The path to the JSON file is provided via `-f` or `--fields`
parameters.

Sample template and fields files can be found inside subfolder `examples/`.

When the `--fields-eval` cli option is provided, `wsctl` evaluates the values of the
fields in the root structure of the JSON document. That means special tokens (expressions)
are replaced if the value of the field is a string matching one of the next:

  * `"$uuid"` - replace with a UUID value
  * `"$randseq"` - replace with a random number from `1` to `1 000 000`.
  * `"$datefull"` - replace with output of `time.Now().String()`
  * `"$daterfc1123"` - replace with output of `time.Now().Format(time.RFC1123)`
  * `"$dateansic"` - replace with output of `time.Now().Format(time.ANSIC)`
  * `"$dateunix"` - replace with output of `time.Now().Format(time.UnixDate)`
  * `"$timestamp"` - replace with output of `time.Now().Unix()`
  * `"$cr"` - replace with `\r`
  * `"$lf"` - replace with `\n`

Example:

```json
{
	"caller": "alice",
	"callee": "bob",
	"domain": "localhost",
	"fromtag": "$uuid",
	"callid": "$uuid",
	"cseqnum": "$randseq"
}
```

The internal fields data can be found at the top of `wsctl.go` file.

The values for fields can be also provided using `--field-val` cli parameter, in
format `name:value`, for example:

```
wsctl --field-val="domain:openrcs.com" ...
```

The value provided via `--field-val` overwrites the value provided in the
JSON fields file.

## Internals ##

Sending data over websocket connection has a timeout of 10 seconds. Receiving data from websocket connection has a timeout of 20 seconds. These values can be changed via command line parameters.

## WebSocket Server Mode ##

To be started as a WebSocket server, `wsctl` must be given `-http-srv` or `-https-srv` command
line parameter. Their value has to be `:PORT` to listen on all local IP address,
or `LOCALIP:PORT` to listen only on a specific local IP.

## Contributions ##

Contributions are welcome! Fork and do pull requests on https://github.com/miconda/wsctl .

## To-Do ##

Just some ideas for now, not all to be implemented:

  * open many websocket connections at once and send data on all of them (tool for stress testing)
  * option to specify some of the command line parameters via fields file (e.g., auth username, password)
  * support to work with an array of templates and fields files

Suggestions for what to add are welcome as well!
