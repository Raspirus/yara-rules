
rule SIGNATURE_BASE_SUSP_Microsoft_7Z_SFX_Combo : FILE
{
	meta:
		description = "Detects a suspicious file that has a Microsoft copyright and is a 7z SFX"
		author = "Florian Roth (Nextron Systems)"
		id = "9163a689-c3ee-59b1-bf58-aef5d3072be6"
		date = "2018-09-16"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_sfx_with_microsoft_copyright.yar#L1-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f48887e0c1031d180e25f2d1b9e016d434f594aef283ab3af8418e86496d2eac"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "cce63f209ee4efb4f0419fb4bbb32326392b5ef85cfba80b5b42b861637f1ff1"

	strings:
		$s1 = "7ZSfx%03x.cmd" fullword wide
		$s2 = "7z SFX: error" fullword ascii
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