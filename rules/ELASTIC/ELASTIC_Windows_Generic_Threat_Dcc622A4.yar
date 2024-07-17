rule ELASTIC_Windows_Generic_Threat_Dcc622A4 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "dcc622a4-5c10-463b-a950-fc728f990bca"
		date = "2024-02-14"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2620-L2638"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "94a3f10396c07783586070119becf0924de9a7caf449d6e07065837d54e6222d"
		logic_hash = "9254226918f39389ccc347de1c5064552a8500ccef1884b8e27b6e98c651f45b"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "b47bd4baa68dc56948f29882cf5762b0af2d9f2a837349add4f5d0a8d4152cb2"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 5B 21 5D 20 45 72 72 6F 72 20 77 72 69 74 69 6E 67 20 73 68 65 6C 6C 63 6F 64 65 20 74 6F 20 74 68 65 20 74 61 72 67 65 74 20 64 72 69 76 65 72 2C 20 61 62 6F 72 74 }

	condition:
		all of them
}