rule ELASTIC_Windows_Generic_Threat_0A640296 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "0a640296-0813-4cd3-b55b-01b3689e73d9"
		date = "2024-03-04"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2840-L2858"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3682eff62caaf2c90adef447d3ff48a3f9c34c571046f379d2eaf121976f1d07"
		logic_hash = "743c47c7a58e7d65261818b4b444aaf8015b9b55d3e54526b1d63a8770a6c5aa"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3fa8712dbf0cdb0581fc312bcfa2e9ea50e04cccba6dc93f377c1b64e96784aa"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 28 00 00 0A 02 7B 0F 00 00 04 6F 29 00 00 0A 7D 10 00 00 04 02 7B 10 00 00 04 28 2A 00 00 0A 00 02 7B 08 00 00 04 7B 03 00 00 04 02 7B 10 00 00 04 6F 2B 00 00 0A 16 FE 01 0D 09 39 29 01 00 00 }

	condition:
		all of them
}