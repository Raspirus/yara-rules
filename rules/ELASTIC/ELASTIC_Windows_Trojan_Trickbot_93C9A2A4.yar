rule ELASTIC_Windows_Trojan_Trickbot_93C9A2A4 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "93c9a2a4-a07a-4ed4-a899-b160d235bf50"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L79-L96"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "dadeeba6147b118b80e014ab067eac7a2c3c2990958a6c7016562d8b64fef53c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0ff82bf9e70304868ff033f0d96e2a140af6e40c09045d12499447ffb94ab838"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 6A 01 8B CF FF 50 5C 8B 4F 58 49 89 4F 64 8B 4D F4 8B 45 E4 }

	condition:
		all of them
}