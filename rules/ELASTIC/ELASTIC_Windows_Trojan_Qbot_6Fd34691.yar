rule ELASTIC_Windows_Trojan_Qbot_6Fd34691 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Qbot (Windows.Trojan.Qbot)"
		author = "Elastic Security"
		id = "6fd34691-10e4-4a66-85ff-1b67ed3da4dd"
		date = "2022-03-07"
		modified = "2022-04-12"
		reference = "https://www.elastic.co/security-labs/exploring-the-qbot-attack-pattern"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Qbot.yar#L44-L64"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0838cd11d6f504203ea98f78cac8f066eb2096a2af16d27fb9903484e7e6a689"
		logic_hash = "9422d9f276f0c8c2990ece3282d918abc6fcce7eeb6809d46ae6b768a501a877"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "187fc04abcba81a2cbbe839adf99b8ab823cbf65993c8780d25e7874ac185695"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 75 C9 8B 45 1C 89 45 A4 8B 45 18 89 45 A8 8B 45 14 89 45 AC 8B }
		$a2 = "\\stager_1.obf\\Benign\\mfc\\" wide

	condition:
		any of them
}