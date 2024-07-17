rule ELASTIC_Windows_Trojan_Vidar_9007Feb2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Vidar (Windows.Trojan.Vidar)"
		author = "Elastic Security"
		id = "9007feb2-6ad1-47b6-bae2-3379d114e4f1"
		date = "2021-06-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Vidar.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "34c0cb6eaf2171d3ab9934fe3f962e4e5f5e8528c325abfe464d3c02e5f939ec"
		logic_hash = "fcdef7397f17ee402155e526c6fa8b51f3ea96e203a095b0b4c36cb7d3cc83d1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8416b14346f833264e32c63253ea0b0fe28e5244302b2e1b266749c543980fe2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { E8 53 FF D6 50 FF D7 8B 45 F0 8D 48 01 8A 10 40 3A D3 75 F9 }

	condition:
		all of them
}