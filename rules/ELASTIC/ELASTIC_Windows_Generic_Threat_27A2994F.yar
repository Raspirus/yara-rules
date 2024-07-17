
rule ELASTIC_Windows_Generic_Threat_27A2994F : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "27a2994f-18e4-4608-bda6-ee76b6afd357"
		date = "2024-02-20"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2700-L2718"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e534914e06d90e119ce87f5abb446c57ec3473a29a7a9e7dc066fdc00dc68adc"
		logic_hash = "66f34ba3052e2369528aeaf076f10d58f8f3dca420666246e02191fecb057f8c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "33d3f5b2c5fed68b19e14d6a35ee8db4ba3d6d566c87e24fc7a9223235cbd0ee"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 51 53 56 57 83 7D 08 00 75 05 E9 88 00 00 00 6A 09 E8 D7 FD FF FF 83 C4 04 8B 45 08 83 E8 20 89 45 FC 8B 4D FC 8B 51 14 81 E2 FF FF 00 00 83 FA 04 74 41 8B 45 FC 83 78 14 01 74 38 8B }

	condition:
		all of them
}