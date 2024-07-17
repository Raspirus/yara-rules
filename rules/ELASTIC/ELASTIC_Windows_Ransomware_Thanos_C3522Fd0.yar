rule ELASTIC_Windows_Ransomware_Thanos_C3522Fd0 : BETA FILE MEMORY
{
	meta:
		description = "Identifies THANOS (Hakbit) ransomware"
		author = "Elastic Security"
		id = "c3522fd0-90e2-4dd9-82f1-4502689270dd"
		date = "2020-11-03"
		modified = "2021-08-23"
		reference = "https://labs.sentinelone.com/thanos-ransomware-riplace-bootlocker-and-more-added-to-feature-set/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Thanos.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "00d28aafd242308ad6561547ed8c80dad3086859dacab09ffdd43d436bf9ec52"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "6d9d6131fd0e3a8585900f4966cb2d1b32e7f5d71b9a65b7a47d80e94bd9f89a"
		threat_name = "Windows.Ransomware.Thanos"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$c1 = { 0C 89 45 F0 83 65 EC 00 EB 07 8B 45 EC 40 89 45 EC 83 7D EC 18 }
		$c2 = { E8 C1 E0 04 8B 4D FC C6 44 01 09 00 8B 45 E8 C1 E0 04 8B 4D FC 83 64 01 }
		$c3 = { 00 2F 00 18 46 00 54 00 50 00 20 00 55 00 73 00 65 00 72 00 4E 00 }

	condition:
		2 of ($c*)
}