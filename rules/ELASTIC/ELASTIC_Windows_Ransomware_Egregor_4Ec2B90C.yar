rule ELASTIC_Windows_Ransomware_Egregor_4Ec2B90C : BETA FILE MEMORY
{
	meta:
		description = "Identifies EGREGOR (Sekhemt) ransomware"
		author = "Elastic Security"
		id = "4ec2b90c-b2de-463d-a9c6-478c255c2352"
		date = "2020-10-15"
		modified = "2021-08-23"
		reference = "https://www.bankinfosecurity.com/egregor-ransomware-adds-to-data-leak-trend-a-15110"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Egregor.yar#L27-L48"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "8342d92e1486b1289645828e5ee5f1f6f21a0e645dd7cc4eca908ed59c2f1c4c"
		score = 75
		quality = 73
		tags = "BETA, FILE, MEMORY"
		fingerprint = "6ae13632f50af11626250c30f570370da23deb265ff6c1fefd2e294c8c170998"
		threat_name = "Windows.Ransomware.Egregor"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$b1 = { 18 F5 46 E0 5C 94 28 B3 5C 94 28 B3 5C 94 28 B3 E8 08 D9 B3 55 94 28 B3 E8 08 DB B3 29 94 28 B3 E8 08 DA B3 44 94 28 B3 67 CA 2B B2 4D 94 28 B3 67 CA 2D B2 47 94 28 B3 67 CA 2C B2 4C 94 28 B3 81 6B E3 B3 5F 94 28 B3 5C 94 29 B3 02 94 28 B3 5C 94 28 B3 5F 94 28 B3 CE CA 28 B2 5D 94 28 B3 CE CA 2A B2 5D 94 28 B3 }
		$b2 = { 34 4F 51 46 33 5C 45 6A 75 5E 7E 4E 37 53 49 7C 49 50 4B 32 73 43 47 5E 68 43 42 4E 7C 42 30 48 62 4C 34 6D 3C 2F 36 76 3D 43 5D 6B 4F 30 32 6E 60 35 68 40 33 60 4B 47 6F 33 55 36 71 56 4A 3D 40 5C 6A 69 4B 4A 60 5C 35 2B 6B 40 33 31 5C 63 7D 4A 47 42 51 5D 70 54 68 7D 62 32 4B 72 6A 57 3C 71 }
		$b3 = { BB 05 10 D4 BB 05 10 E0 BB 05 10 EC BB 05 10 F8 BB 05 10 04 BC 05 10 10 BC 05 10 1C BC 05 10 2C BC 05 10 3C BC 05 10 50 BC 05 10 68 BC 05 10 80 BC 05 10 90 BC 05 10 A8 BC 05 10 B4 BC 05 10 C0 }

	condition:
		1 of ($b*)
}