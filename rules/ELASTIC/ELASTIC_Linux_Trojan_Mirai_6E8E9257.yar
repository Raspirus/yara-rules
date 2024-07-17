rule ELASTIC_Linux_Trojan_Mirai_6E8E9257 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "6e8e9257-a6d5-407a-a584-4656816a3ddc"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1284-L1301"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "67973257e578783838f18dc8ae994f221ad1c1b3f4a04a2b6b523da5ebd8c95b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4bad14aebb0b8c7aa414f38866baaf1f4b350b2026735de24bcf2014ff4b0a6a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 53 83 EC 04 8B 5C 24 18 8B 7C 24 20 8A 44 24 14 8A 54 24 1C 88 54 }

	condition:
		all of them
}