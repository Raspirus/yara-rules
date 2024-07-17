
rule SIGNATURE_BASE_SUSP_Microsoft_RAR_SFX_Combo : FILE
{
	meta:
		description = "Detects a suspicious file that has a Microsoft copyright and is a RAR SFX"
		author = "Florian Roth (Nextron Systems)"
		id = "0fa81a9e-2f41-5783-9786-bb6d33b82bd9"
		date = "2018-09-16"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_sfx_with_microsoft_copyright.yar#L27-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a0f29fcf86139a6f95b4ab0095154bd26b555f1576b5a2e263c1939bc30e3431"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "winrarsfxmappingfile.tmp" fullword wide
		$s2 = "WinRAR self-extracting archive" fullword wide
		$s3 = "WINRAR.SFX" fullword
		$c1 = { 00 4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70
              00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 A9
              00 20 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F
              00 66 00 74 00 20 00 43 00 6F 00 72 00 70 00 6F
              00 72 00 61 00 74 00 69 00 6F 00 6E 00 2E 00 20
              00 41 00 6C 00 6C 00 20 00 72 00 69 00 67 00 68
              00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72
              00 76 00 65 00 64 00 2E }

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 1 of ($s*) and $c1
}