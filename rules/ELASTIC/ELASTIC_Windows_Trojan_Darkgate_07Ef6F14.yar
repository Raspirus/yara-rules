rule ELASTIC_Windows_Trojan_Darkgate_07Ef6F14 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Darkgate (Windows.Trojan.DarkGate)"
		author = "Elastic Security"
		id = "07ef6f14-4eb5-4c15-94af-117c68106104"
		date = "2023-12-14"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_DarkGate.yar#L23-L42"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1fce9ee9254dd0641387cc3b6ea5f6a60f4753132c20ca03ce4eed2aa1042876"
		logic_hash = "2820286b362b107fc7fc3ec8f1a004a7d7926a84318f2943f58239f1f7e8f1f0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fd0aab53bddd3872147aa064a571d118cc00a6643d72c017fe26f6e0d19288e1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$binary0 = { 8B 04 24 0F B6 44 18 FF 33 F8 43 4E }
		$binary1 = { 8B D7 32 54 1D FF F6 D2 88 54 18 FF 43 4E }

	condition:
		all of them
}