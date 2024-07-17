
rule ELASTIC_Linux_Ransomware_Royalpest_502A3Db6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Royalpest (Linux.Ransomware.RoyalPest)"
		author = "Elastic Security"
		id = "502a3db6-4711-42c7-8178-c3150f184fc6"
		date = "2023-07-27"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_RoyalPest.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "09a79e5e20fa4f5aae610c8ce3fe954029a91972b56c6576035ff7e0ec4c1d14"
		logic_hash = "aefb5a286636b827b50e4bc0ea978a75ba6a9e572504bfbc0a7700372c54a077"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4bde7998f41ef3d0f2769078cf56e03d36eacf503f859a23fc442ced95d839cb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "hit by Royal ransomware."
		$a2 = "Please contact us via :"
		$a3 = ".onion/%s"
		$a4 = "esxcli vm process list > list"

	condition:
		3 of them
}