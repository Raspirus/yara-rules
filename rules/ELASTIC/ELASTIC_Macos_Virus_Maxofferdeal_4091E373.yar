rule ELASTIC_Macos_Virus_Maxofferdeal_4091E373 : FILE MEMORY
{
	meta:
		description = "Detects Macos Virus Maxofferdeal (MacOS.Virus.Maxofferdeal)"
		author = "Elastic Security"
		id = "4091e373-c3a9-41c8-a1d8-3a77585ff850"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Virus_Maxofferdeal.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c38c4bdd3c1fa16fd32db06d44d0db1b25bb099462f8d2936dbdd42af325b37c"
		logic_hash = "ce82f6d3a2e4b7ffe7010629bf91a9144a94e50513682a6c0622603d28248d51"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3d8e7db6c39286d9626c6be8bfb5da177a6a4f8ffcec83975a644aaac164a8c7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { B8 F2 E7 E7 BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 8B 8E 8A BD A6 AC A4 }

	condition:
		all of them
}