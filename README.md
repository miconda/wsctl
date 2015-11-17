# wsctl
WebSocket Command Line Tool

License: GPLv2

## Overview

**wsctl** is a websocket client to be used from command line. It is written in Go (Golang).

While the common use case for websocket connections is between web browser and web server, there are situations where is more convenient to use a command line (e.g., testing).

**wsctl** can send data loaded from a template file to a websocket server and it will print the response received from the server.

It was developed and tested for sending SIP requests over websocket to Kamailio SIP Server (http://www.kamailio.org), but the data can be any format.

For SIP over websocket, it can do www-digest authentication if the server challenges with a 401/407 response.

## Install

First install Go (http://golang.org). Once the Go environment is configured, the websocket package must be fetched locally:

```
go get -v golang.org/x/net/websocket
```

Fetch this repository into your Go environment:

```
go get -v -u github.com/miconda/wsctl
```

### Run

Navivate to the project folder and run:

```
go run wsctl.go [options]
```

Or install the application:

```
go install github.com/miconda/wsctl
```

And the run:

```
$GOPATH/bin/wsctl [options]
```

## Command Line Options

If run with option '-h' or '--help', it will print the help message.

If run without any option, it attempts to send a SIP OPTIONS request to wss://127.0.0.1:8443.

To run using external template and fields files, to send data to a particular WS server over secure connection:

```
go run wsctl.go \
   --url='wss://myserver.com:8443/ws' \
   --template=examples/tpl-options-aa.sip \
   --fields=examples/fld-options-aa.json
```

To provide username and password for www-digest authentication of SIP requests:

```
go run wsctl.go \
   --url='wss://myserver.com:8443/ws' \
   --template=examples/tpl-options-aa.sip \
   --fields=examples/fld-options-aa.json \
   --auser='test' --apasswd='secret'
```

For websocket secure connections (wss), by default it skips server's TLS certificate verification. To enforce certificate verification add the command line option '--insecure=false'.

The http url for Origin header can be set with option '--origin=...'.

The websocket subprotocol can be set with option '--protocol=...'.

## Data Templates

The data to be sent via the websocket connection is built from a template file and a fields file.

The template file can contain any any of the dirrectives supported by Go package "text/template" - for more see:

  * https://golang.org/pkg/text/template/

The fields file has to contain a JSON document with the fields to be replaced in the template file.

Sample template and fields files can be found inside subfolder "examples/".

## Internals

Sending data over websocket connection has a timeout of 10 seconds. Receiving data from websocket connection has a timeout of 20 seconds.

## Contributions

Contributions are welcome! Fork and do pull requests on https://github.com/miconda/wsctl .

## To-Do

Just some ideas for now, not all to be implemented:

  * open many websocket connections at once and send data on all of them (tool for stress testing)
  * option to specify some of the command line parameters via fields file (e.g., auth username, password)
  * support to work with an array of templates and fields files

Suggestions for what to add are welcome as well!
