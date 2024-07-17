
rule ELASTIC_Windows_Hacktool_Processhacker_3D01069E : FILE
{
	meta:
		description = "Detects Windows Hacktool Processhacker (Windows.Hacktool.ProcessHacker)"
		author = "Elastic Security"
		id = "3d01069e-7afb-4da0-b7ac-23f90db26495"
		date = "2022-03-30"
		modified = "2022-03-30"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_ProcessHacker.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "70211a3f90376bbc61f49c22a63075d1d4ddd53f0aefa976216c46e6ba39a9f4"
		logic_hash = "bcba74aa20b62329c48060bfebaf49ab12f89f9ec3a09fc0c0cb702de5e2b940"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "5d6a0835ac6c0548292ff11741428d7b2f4421ead6d9e2ca35379cbceb6ee68c"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = "OriginalFilename\x00kprocesshacker.sys" wide fullword

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name
}