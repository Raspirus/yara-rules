import "pe"


rule SIGNATURE_BASE_Oilrig_Ismagent_Campaign_Samples2 : FILE
{
	meta:
		description = "Detects OilRig malware from Unit 42 report in October 2017"
		author = "Florian Roth (Nextron Systems)"
		id = "08771b23-1d0e-5da7-b42c-005ed257e2d1"
		date = "2017-10-18"
		modified = "2023-12-05"
		reference = "https://goo.gl/JQVfFP"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_oilrig_oct17.yar#L63-L82"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ad00c7293f61f1b5528c3eea0dc32c10d40aeacc194be84a7f64d19b069f1add"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fcad263d0fe2b418db05f47d4036f0b42aaf201c9b91281dfdcb3201b298e4f4"
		hash2 = "33c187cfd9e3b68c3089c27ac64a519ccc951ccb3c74d75179c520f54f11f647"

	strings:
		$x1 = "PolicyConverter.exe" fullword wide
		$x2 = "SrvHealth.exe" fullword wide
		$x3 = "srvBS.txt" fullword wide
		$s1 = "{a3538ba3-5cf7-43f0-bc0e-9b53a98e1643}, PublicKeyToken=3e56350693f7355e" fullword wide
		$s2 = "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\RegAsm.exe" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <700KB and (2 of ($x*) or 3 of them )
}