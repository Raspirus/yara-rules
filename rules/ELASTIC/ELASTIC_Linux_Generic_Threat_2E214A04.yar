rule ELASTIC_Linux_Generic_Threat_2E214A04 : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "2e214a04-43a4-4c26-8737-e089fbf6eecd"
		date = "2024-01-17"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L62-L81"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "cad65816cc1a83c131fad63a545a4bd0bdaa45ea8cf039cbc6191e3c9f19dead"
		logic_hash = "0d29aa6214b0a05f9af10cdc080ffa33452156e13c057f31997630cebcda294a"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "0937f7c5bcfd6f2b327981367684cff5a53d35c87eaa360e90afc9fce1aec070"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 49 6E 73 65 72 74 20 76 69 63 74 69 6D 20 49 50 3A 20 }
		$a2 = { 49 6E 73 65 72 74 20 75 6E 75 73 65 64 20 49 50 3A 20 }

	condition:
		all of them
}