rule ELASTIC_Windows_Trojan_Trickbot_Cd0868D5 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "cd0868d5-42d8-437f-8c1a-303526c08442"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L136-L153"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "053a99e5e722fd2aa1cae96266cc344954f9c3a12d0851fa9d5e95a6420651f4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2f777285a90fce20cd4eab203f3ec7ed1c62e09fc2dfdce09b57e0802f49628f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 8D 1C 01 89 54 24 10 8B 54 24 1C 33 C9 66 8B 0B 8D 3C 8A 8B 4C }

	condition:
		all of them
}