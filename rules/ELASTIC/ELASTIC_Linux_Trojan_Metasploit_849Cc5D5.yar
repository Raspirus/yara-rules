
rule ELASTIC_Linux_Trojan_Metasploit_849Cc5D5 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Metasploit (Linux.Trojan.Metasploit)"
		author = "Elastic Security"
		id = "849cc5d5-737a-4ea4-9bb6-cec26b132ff2"
		date = "2024-05-03"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Metasploit.yar#L50-L71"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "42d734dbd33295bd68e5a545a29303a2104a5a92e5fee31d645e2a6410cc03e9"
		logic_hash = "01c708b1e000aecf473e0a1cf23f3812a337b9b21f5b81f7a5e481d06fdaeb16"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "859638998983b9dc0cffc204985b2c4db8a4fb2a97ff4e791fd6762ff6b1f5da"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$init1 = { 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 48 97 }
		$init2 = { 6A 10 5A 6A ?? 58 0F }
		$shell1 = { 6A 03 5E 48 FF CE 6A 21 58 0F 05 75 F6 6A 3B 58 99 48 BB 2F 62 69 6E 2F 73 68 00 53 48 89 E7 52 57 48 89 E6 0F 05 }
		$shell2 = { 48 96 6A 2B 58 0F 05 50 56 5F 6A 09 58 99 B6 10 48 89 D6 4D 31 C9 6A 22 41 5A B2 07 0F 05 48 96 48 97 5F 0F 05 FF E6 }

	condition:
		all of ($init*) and 1 of ($shell*)
}