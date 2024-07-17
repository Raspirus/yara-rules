rule ELASTIC_Macos_Trojan_Bundlore_7B9F0C28 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
		author = "Elastic Security"
		id = "7b9f0c28-181d-4fdc-8a57-467d5105129a"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Bundlore.yar#L201-L219"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fc4da125fed359d3e1740dafaa06f4db1ffc91dbf22fd5e7993acf8597c4c283"
		logic_hash = "32abbb76c866e3a555ee6a9c39f62a0712f641959b66068abfb4379baa9a9da9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dde16fdd37a16fa4dae24324283cd4b36ed2eb78f486cedd1a6c7bef7cde7370"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 35 B6 15 00 00 81 80 35 B0 15 00 00 14 80 35 AA 15 00 00 BC 80 35 A4 15 00 00 }

	condition:
		all of them
}