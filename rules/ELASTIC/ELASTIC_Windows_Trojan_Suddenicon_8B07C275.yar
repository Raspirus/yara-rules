rule ELASTIC_Windows_Trojan_Suddenicon_8B07C275 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Suddenicon (Windows.Trojan.SuddenIcon)"
		author = "Elastic Security"
		id = "8b07c275-f389-4e55-bcec-4b1344cad33d"
		date = "2023-03-29"
		modified = "2023-03-30"
		reference = "https://www.elastic.co/security-labs/elastic-users-protected-from-suddenicon-supply-chain-attack"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_SuddenIcon.yar#L28-L48"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973"
		logic_hash = "64e8bd8929c9fb8cae16f772e3266b02b4ddec770ff8d5379a93a483eb8ff660"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "482f1e668ab63be44a249274e0eaa167e1418c42a8f0e9e85b26e4e23ff57a0d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = { 33 C9 E8 ?? ?? ?? ?? 48 8B D8 E8 ?? ?? ?? ?? 44 8B C0 B8 ?? ?? ?? ?? 41 F7 E8 8D 83 ?? ?? ?? ?? C1 FA ?? 8B CA C1 E9 ?? 03 D1 69 CA ?? ?? ?? ?? 48 8D 55 ?? 44 2B C1 48 8D 4C 24 ?? 41 03 C0 }
		$str2 = { B8 ?? ?? ?? ?? 41 BA ?? ?? ?? ?? 0F 11 84 24 ?? ?? ?? ?? 44 8B 06 8B DD BF ?? ?? ?? ?? }

	condition:
		all of them
}