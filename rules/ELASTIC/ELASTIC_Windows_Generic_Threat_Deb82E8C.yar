
rule ELASTIC_Windows_Generic_Threat_Deb82E8C : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "deb82e8c-57dc-47ea-a786-b4e1ae41a40f"
		date = "2024-01-31"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2416-L2435"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0f5791588a9898a3db29326785d31b52b524c3097370f6aa28564473d353cd38"
		logic_hash = "c24baecab39c72f6bb30713022297cb9fb41ef5339a353702f3f780a630d5b27"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "3429ecf8f509c6833b790156e61f0d1a6e0dc259d4891d6150a99b5cb3f0f26e"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 50 6F 76 65 72 74 79 20 69 73 20 74 68 65 20 70 61 72 65 6E 74 20 6F 66 20 63 72 69 6D 65 2E }
		$a2 = { 2D 20 53 79 73 74 65 6D 4C 61 79 6F 75 74 20 25 64 }

	condition:
		all of them
}