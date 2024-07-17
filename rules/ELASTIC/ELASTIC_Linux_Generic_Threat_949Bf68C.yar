rule ELASTIC_Linux_Generic_Threat_949Bf68C : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "949bf68c-e6a0-451d-9e49-4515954aabc8"
		date = "2024-02-21"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L821-L839"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "cc1b339ff6b33912a8713c192e8743d1207917825b62b6f585ab7c8d6ab4c044"
		logic_hash = "aaae0a8a2827786513891bc8c3e3418823ae3f3291d891e80e82113b929f7513"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e478c8befed6da3cdd9985515e4650a8b7dad1ea28292c2cf91069856155facd"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 55 89 E5 57 56 53 81 EC 58 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 85 B4 FE FF FF 89 95 AC FE FF FF 8D B5 C4 FE FF FF 56 ?? ?? ?? ?? ?? 58 5A 6A 01 56 }

	condition:
		all of them
}