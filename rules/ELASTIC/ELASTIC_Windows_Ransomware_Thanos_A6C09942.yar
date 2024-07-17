
rule ELASTIC_Windows_Ransomware_Thanos_A6C09942 : BETA FILE MEMORY
{
	meta:
		description = "Identifies THANOS (Hakbit) ransomware"
		author = "Elastic Security"
		id = "a6c09942-0733-40d7-87b7-eb44dd472a35"
		date = "2020-11-03"
		modified = "2021-08-23"
		reference = "https://labs.sentinelone.com/thanos-ransomware-riplace-bootlocker-and-more-added-to-feature-set/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Thanos.yar#L24-L44"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "cecdeb21e041c90769b8fd8431fa87943461c1f7faa5ad15918524b91ba5c792"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "4abcf47243bebc281566ba4929b20950e3f1bfac8976ae5bc6b8ffda85468ec0"
		threat_name = "Windows.Ransomware.Thanos"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$b1 = { 00 57 00 78 00 73 00 49 00 48 00 6C 00 76 00 64 00 58 00 49 00 67 00 5A 00 6D 00 6C 00 73 00 5A 00 58 00 4D 00 67 00 64 00 32 00 56 00 79 00 5A 00 53 00 42 00 6C 00 62 00 6D 00 4E 00 79 00 65 00 58 00 42 00 30 00 5A 00 57 00 51 00 73 00 49 00 47 00 6C 00 6D 00 49 00 48 00 6C 00 76 00 64 00 53 00 42 00 33 00 59 00 57 00 35 00 30 00 49 00 48 00 52 00 76 00 49 00 47 00 64 00 6C 00 64 00 43 00 42 00 30 00 61 00 47 00 56 00 74 00 49 00 47 00 46 00 73 00 62 00 43 00 42 00 69 00 59 00 57 00 4E 00 72 00 4C 00 43 00 42 00 77 00 62 00 47 00 56 00 68 00 63 00 32 00 55 00 67 00 59 00 32 00 46 00 79 00 5A 00 57 00 5A 00 31 00 62 00 47 00 78 00 35 00 49 00 48 00 4A 00 6C 00 59 00 57 00 51 00 67 00 64 00 47 00 68 00 6C 00 49 00 48 00 52 00 6C 00 65 00 48 00 51 00 67 00 62 00 6D 00 39 00 30 00 5A 00 53 00 42 00 73 00 62 00 32 00 4E 00 68 00 64 00 47 00 56 00 6B 00 49 00 47 00 6C 00 75 00 49 00 48 00 6C 00 76 00 64 00 58 00 49 00 67 00 5A 00 47 00 56 00 7A 00 61 00 33 00 52 00 76 00 63 00 43 00 34 00 75 00 4C 00 67 00 3D 00 3D }
		$b2 = { 01 0E 0E 05 00 02 0E 0E 0E 04 00 01 01 0E 04 00 01 0E 0E 06 00 03 01 0E 0E 0E 80 90 55 00 30 00 39 00 47 00 56 00 46 00 64 00 42 00 55 00 6B 00 56 00 63 00 54 00 57 00 6C 00 6A 00 63 00 6D 00 39 00 7A 00 62 00 32 00 5A 00 30 00 58 00 46 00 64 00 70 00 62 00 6D 00 52 00 76 00 64 00 33 00 4D 00 67 00 54 00 6C 00 52 00 63 00 51 00 33 00 56 00 79 00 63 00 6D 00 56 00 75 00 64 00 46 00 5A 00 6C 00 63 00 6E 00 4E 00 70 00 62 00 32 00 35 00 63 00 56 00 32 00 6C 00 }

	condition:
		1 of ($b*)
}