import "pe"


rule SIGNATURE_BASE_TA17_293A_Hacktool_Touch_MAC_Modification : FILE
{
	meta:
		description = "Auto-generated rule"
		author = "Florian Roth (Nextron Systems)"
		id = "69240cc0-a04e-544a-b7e3-c5a08c062055"
		date = "2017-10-21"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ta17_293A.yar#L168-L184"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5f4c6b653d1b6f4427c6582513d3c19cb8d580e669260a1afda01eecf8ce3bfc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "070d7082a5abe1112615877214ec82241fd17e5bd465e24d794a470f699af88e"

	strings:
		$s1 = "-t time - use the time specified to update the access and modification times" fullword ascii
		$s2 = "Failed to set file times for %s. Error: %x" fullword ascii
		$s3 = "touch [-acm][ -r ref_file | -t time] file..." fullword ascii
		$s4 = "-m - change the modification time only" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 1 of them )
}