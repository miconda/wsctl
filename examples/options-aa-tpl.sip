OPTIONS sip:{{.callee}}@{{.domain}} SIP/2.0
Via: SIP/2.0/WSS df7jal23ls0d.invalid;branch=z9hG4bKasudf-3696-24845-1
From: '{{.caller}}' <sip:{{.caller}}@{{.domain}}>;tag=d71a60e3-c5f6-4b17-a8b6-d08c6a690ae4
To: '{{.callee}}' <sip:{{.callee}}@{{.domain}}>
Call-ID: deefd8e1-993e-4552-8a1b-4f3d9390485e
CSeq: 2 OPTIONS
Subject: testing
Content-Length: 0

