rule ELASTIC_Linux_Trojan_Mirai_994535C4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "994535c4-77a6-4cc6-b673-ce120be8d0f4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1323-L1341"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "376a2771a2a973628e22379b3dbb9a8015c828505bbe18a0c027b5d513c9e90d"
		logic_hash = "c83c8c9cdfea1bf322115e5b23d751b226a5dbf42fc41faac172d36192ccf31f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a3753e29ecf64bef21e062b8dec96ba9066f665919d60976657b0991c55b827b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 20 74 07 31 C0 48 FF C3 EB EA FF C0 83 F8 08 75 F4 48 8D 73 03 }

	condition:
		all of them
}