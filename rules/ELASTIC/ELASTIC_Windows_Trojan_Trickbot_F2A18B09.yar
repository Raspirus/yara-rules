
rule ELASTIC_Windows_Trojan_Trickbot_F2A18B09 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "f2a18b09-f7b3-4d1a-87ab-3018f520b69c"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L250-L267"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "c4c4b0b1df1e8fde87284fb27d46e917c47b479a675fec60faeca6185511907d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3e4474205efe22ea0185c49052e259bc08de8da7c924372f6eb984ae36b91a1c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 04 39 45 08 75 08 8B 4D F8 8B 41 18 EB 0F 8B 55 F8 8B 02 89 }

	condition:
		all of them
}