
rule ELASTIC_Linux_Ransomware_Ragnarlocker_9F5982B8 : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Ragnarlocker (Linux.Ransomware.RagnarLocker)"
		author = "Elastic Security"
		id = "9f5982b8-98db-42d1-b987-451d3cb7fc4b"
		date = "2023-07-27"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_RagnarLocker.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f668f74d8808f5658153ff3e6aee8653b6324ada70a4aa2034dfa20d96875836"
		logic_hash = "c08579dc675a709add392a0189d01e05af61034b72f451d2b024c89c1299ee6c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "782d9225a6060c23484a285f7492bb45f21c37597ea82e4ca309aedbb1c30223"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = ".README_TO_RESTORE"
		$a2 = "If WE MAKE A DEAL:"
		$a3 = "Unable to rename file from: %s to: %s"

	condition:
		2 of them
}