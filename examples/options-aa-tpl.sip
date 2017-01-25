OPTIONS sip:{{.callee}}@{{.domain}} SIP/2.0
Via: SIP/2.0/WSS df7jal23ls0d.invalid;branch=z9hG4bKasudf-3696-24845-1
From: '{{.caller}}' <sip:{{.caller}}@{{.domain}}>;tag=3696-0024845
To: '{{.callee}}' <sip:{{.callee}}@{{.domain}}>
Call-ID: 24845-3696@127.0.0.1
CSeq: 2 OPTIONS
Subject: testing
Content-Length: 0

