rule SIGNATURE_BASE_Sofacy_Campaign_Mal_Feb18_Cdnver : FILE
{
	meta:
		description = "Detects Sofacy malware"
		author = "Florian Roth (Nextron Systems)"
		id = "a5c72ddd-91b0-5410-9d81-38a138ec7efe"
		date = "2018-02-07"
		modified = "2023-12-05"
		reference = "https://twitter.com/ClearskySec/status/960924755355369472"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sofacy.yar#L4-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cd3fa21710054a96cc85da13d98e0882deaa574708c833349638b57b6088131c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "12e6642cf6413bdf5388bee663080fa299591b2ba023d069286f3be9647547c8"

	strings:
		$x1 = "cdnver.dll" fullword wide
		$x2 = { 25 73 0A 00 00 00 00 00 30 00 00 00 20 00 2D 00
              20 00 00 00 0A 00 00 00 25 00 73 00 00 00 00 00
              69 00 6D 00 61 00 67 00 65 00 2F 00 6A 00 70 00
              65 00 67 }
		$s1 = "S7%s - %lu" fullword ascii
		$s2 = "SNFIRNW" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <90KB and (pe.imphash()=="01f3d0fe6fb9d9df24620e67afc143c7" or 1 of ($x*) or 2 of them )
}