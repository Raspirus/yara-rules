
rule ELASTIC_Windows_Ransomware_Ryuk_72B5Fd9D : BETA FILE MEMORY
{
	meta:
		description = "Identifies RYUK ransomware"
		author = "Elastic Security"
		id = "72b5fd9d-23db-4f18-88d9-a849ec039135"
		date = "2020-04-30"
		modified = "2021-08-23"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Ryuk.yar#L90-L109"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "b2abc8f70df5d730ce6a7d0bc125bb623f27b292e7d575914368a8bfc0fb5837"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "7c394aa283336013b74a8aaeb56e8363033958b4a1bd8011f3b32cfe2d37e088"
		threat_name = "Windows.Ransomware.Ryuk"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$d1 = { 48 2B C3 33 DB 66 89 1C 46 48 83 FF FF 0F }

	condition:
		1 of ($d*)
}