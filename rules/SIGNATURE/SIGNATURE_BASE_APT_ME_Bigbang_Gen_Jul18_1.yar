import "pe"


rule SIGNATURE_BASE_APT_ME_Bigbang_Gen_Jul18_1 : FILE
{
	meta:
		description = "Detects malware from Big Bang campaign against Palestinian authorities"
		author = "Florian Roth (Nextron Systems)"
		id = "f1097998-9414-511c-b177-ff09154964a8"
		date = "2018-07-09"
		modified = "2023-12-05"
		reference = "https://research.checkpoint.com/apt-attack-middle-east-big-bang/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_bigbang.yar#L3-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "496994ee035aa09233c648cf4ec0d1e84ceb970917b4dc5208a1390ec6eb39c2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4db68522600f2d8aabd255e2da999a9d9c9f1f18491cfce9dadf2296269a172b"
		hash2 = "ac6462e9e26362f711783b9874d46fefce198c4c3ca947a5d4df7842a6c51224"
		hash3 = "e1f52ea30d25289f7a4a5c9d15be97c8a4dfe10eb68ac9d031edcc7275c23dbc"

	strings:
		$x2 = "%@W@%S@c@ri%@p@%t.S@%he@%l%@l" ascii
		$x3 = "S%@h%@e%l%@l." ascii
		$x4 = "(\"S@%t@%a%@rt%@up\")" ascii
		$x5 = "aW5zdGFsbCBwcm9nOiBwcm9nIHdpbGwgZGVsZXRlIG9sZCB0bXAgZmlsZQ==" fullword ascii
		$x6 = "aW5zdGFsbCBwcm9nOiBUaGVyZSBpcyBubyBvbGQgZmlsZSBpbiB0ZW1wLg==" fullword ascii
		$x7 = "VXBkYXRlIHByb2c6IFRoZXJlIGlzIG5vIG9sZCBmaWxlIGluIHRlbXAu" fullword ascii
		$x8 = "aW5zdGFsbCBwcm9nOiBDcmVhdGUgVGFzayBhZnRlciA1IG1pbiB0byBydW4gRmlsZSBmcm9tIHRtcA==" fullword ascii
		$x9 = "UnVuIEZpbGU6IE15IHByb2cgaXMgRXhpdC4=" fullword ascii
		$x10 = "li%@%@nk.W%@%@indo@%%@%@%wS%@%@tyle = 3" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and (1 of them or pe.imphash()=="0f09ea2a68d04f331df9a5d0f8641332")
}