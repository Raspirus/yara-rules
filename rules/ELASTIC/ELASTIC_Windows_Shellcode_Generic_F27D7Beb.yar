
rule ELASTIC_Windows_Shellcode_Generic_F27D7Beb : FILE MEMORY
{
	meta:
		description = "Detects Windows Shellcode Generic (Windows.Shellcode.Generic)"
		author = "Elastic Security"
		id = "f27d7beb-5ce0-4831-b1ad-320b346612c3"
		date = "2022-06-08"
		modified = "2022-09-29"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Shellcode_Generic.yar#L20-L37"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "8530a74a002d0286711cd86545aff0bf853de6b6684473b6211d678797c3639f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3f8dd6733091ec229e1bebe9e4cd370ad47ab2e3678be4c2d9c450df731a6e5c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 53 48 89 E3 66 83 E4 00 48 B9 [8] BA 01 00 00 00 41 B8 00 00 00 00 48 B8 [8] FF D0 48 89 DC 5B C3 }

	condition:
		all of them
}