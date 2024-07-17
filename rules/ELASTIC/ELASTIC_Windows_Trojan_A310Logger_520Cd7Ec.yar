
rule ELASTIC_Windows_Trojan_A310Logger_520Cd7Ec : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan A310Logger (Windows.Trojan.A310logger)"
		author = "Elastic Security"
		id = "520cd7ec-840c-4d45-961b-8bc5e329c52f"
		date = "2022-01-11"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_A310logger.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "60fb9597e5843c72d761525f73ca728409579d81901860981ebd84f7d153cfa3"
		logic_hash = "6095ce913e3fb1cfc2f1b091598fc06b2dfec30c2353be7df08dcbb1a06b07c3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f4ee88e555b7bd0102403cc804372f5376debc59555e8e7b4a16e18b04d1b314"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "/dumps9taw" ascii fullword
		$a2 = "/logstatus" ascii fullword
		$a3 = "/checkprotection" ascii fullword
		$a4 = "[CLIPBOARD]<<" wide fullword
		$a5 = "&chat_id=" wide fullword

	condition:
		all of them
}