
rule ELASTIC_Windows_Trojan_Agenttesla_A2D69E48 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Agenttesla (Windows.Trojan.AgentTesla)"
		author = "Elastic Security"
		id = "a2d69e48-b114-4128-8c2f-6fabee49e152"
		date = "2023-05-01"
		modified = "2023-06-13"
		reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_AgentTesla.yar#L102-L122"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "edef51e59d10993155104d90fcd80175daa5ade63fec260e3272f17b237a6f44"
		logic_hash = "1f90be86b7afa7f518a3dcec55028bfc915cf6d4fed1350a56e351946cc55f41"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bd46dd911aadf8691516a77f3f4f040e6790f36647b5293050ecb8c25da31729"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 00 03 08 08 10 08 10 18 09 00 04 08 18 08 10 08 10 18 0E 00 08 }
		$a2 = { 00 06 17 5F 16 FE 01 16 FE 01 2A 00 03 30 03 00 B1 00 00 00 }

	condition:
		all of them
}