REGISTER sip:{{.domain}} SIP/2.0
Via: SIP/2.0/WSS q72jr0k8gorn.invalid;branch=z9hG4bK428540716
Max-Forwards: 69
To: '{{.caller}}' <sip:{{.caller}}@{{.domain}}>
From: '{{.caller}}' <sip:{{.caller}}@{{.domain}}>;tag=syevwlcxem
Call-ID: 69e069a5-5d2e-4514-9c40-2fbad9e3b8ee
CSeq: 1 REGISTER
Contact: <sip:20n17932@q72jr0k8gorn.invalid;transport=wss>
Expires: {{.expires}}
Allow: INVITE,ACK,CANCEL,BYE,UPDATE,MESSAGE,OPTIONS,REFER,INFO
Supported: path
User-Agent: wsctl
Content-Length: 0

