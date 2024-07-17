import "pe"


rule SIGNATURE_BASE_APT_Winnti_MAL_Dec19_1 : FILE
{
	meta:
		description = "Detects Winnti malware"
		author = "Unknown"
		id = "322e9362-bfb6-55e3-9a93-d54246311d11"
		date = "2019-12-06"
		modified = "2023-12-05"
		reference = "https://www.verfassungsschutz.de/download/broschuere-2019-12-bfv-cyber-brief-2019-01.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti.yar#L160-L176"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9e26a642cfe143b8efc52b2b9789c2ec54592f6347f16fb8716912767e4f9879"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$e1 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411015}" ascii nocase
		$e2 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411014}" ascii nocase
		$e3 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411016}" ascii nocase
		$e4 = "\\BaseNamedObjects\\{B2B87CCA-66BC-4C24-89B2-C23C9EAC2A66}" wide
		$e5 = "BFE_Notify_Event_{7D00FA3C-FBDC-4A8D-AEEB-3F55A4890D2A}" nocase

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and ( any of ($e*))
}