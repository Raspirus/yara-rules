
rule SIGNATURE_BASE_Malrtf_Ole2Link : EXPLOIT FILE
{
	meta:
		description = "Detects weaponized RTF documents with OLE2Link exploit"
		author = "@h3x2b <tracker _AT h3x.eu>"
		id = "5080e79a-3abc-5fc3-902e-b362f20510f9"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/exploit_rtf_ole2link.yar#L1-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d7ef764a0006b81c2b50699aa1fccb35c7c7da982cb8d56e02097114468e298f"
		score = 75
		quality = 85
		tags = "EXPLOIT, FILE"

	strings:
		$rtf_olelink_01 = "\\objdata" nocase
		$rtf_olelink_02 = "4f4c45324c696e6b" nocase
		$rtf_olelink_03 = "d0cf11e0a1b11ae1" nocase
		$rtf_payload_01 = "68007400740070003a002f002f00" nocase
		$rtf_payload_02 = "680074007400700073003a002f002f00" nocase
		$rtf_payload_03 = "6600740070003a002f002f00" nocase

	condition:
		uint32be(0)==0x7B5C7274 and all of ($rtf_olelink_*) and any of ($rtf_payload_*)
}