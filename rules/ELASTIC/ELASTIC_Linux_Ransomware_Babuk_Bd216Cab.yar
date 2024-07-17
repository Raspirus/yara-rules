
rule ELASTIC_Linux_Ransomware_Babuk_Bd216Cab : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Babuk (Linux.Ransomware.Babuk)"
		author = "Elastic Security"
		id = "bd216cab-6532-4a71-9353-8ad692550b97"
		date = "2024-05-09"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_Babuk.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d305a30017baef4f08cee38a851b57869676e45c66e64bb7cc58d40bf0142fe0"
		logic_hash = "b0538be9d8deccc3f77640da28e5fd38a07557e9e5e3c09b11349d7eb50a56b5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c7517a40759de20edf7851d164c0e4ba71de049f8ea964f15ab5db12c35352ad"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "Whole files count: %d"
		$a2 = "Doesn't encrypted files: %d"

	condition:
		all of them
}