rule ELASTIC_Windows_Generic_Threat_Ea296356 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "ea296356-6533-4364-8ad1-3bbb538e3d61"
		date = "2024-05-22"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3384-L3402"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4c48a0fe90f3da7bfdd32961da7771a0124b77e1ac1910168020babe8143e959"
		logic_hash = "73ffd16f0047cd57311853aa9083fc21427f2eb21646c6edc7b8def86da90f90"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a17ca2f95473517428867b4f68b8275ae84ef1ee39421e76887077e206b1ed51"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 83 EC 0C 53 56 8B 75 08 8B C6 89 55 FC 99 2B C2 89 4D F8 8B D8 8B 45 FC 57 D1 FB 33 FF 8D 14 30 89 55 08 85 DB 7E 36 4A 0F 1F 44 00 00 8A 0C 38 8D 52 FF 0F B6 42 01 8B 75 FC 0F B6 80 }

	condition:
		all of them
}