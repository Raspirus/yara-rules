rule ELASTIC_Linux_Ransomware_Noescape_6De58E0C : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Noescape (Linux.Ransomware.NoEscape)"
		author = "Elastic Security"
		id = "6de58e0c-67f9-4344-9fe9-26bfc37e537e"
		date = "2023-07-27"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_NoEscape.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "46f1a4c77896f38a387f785b2af535f8c29d40a105b63a259d295cb14d36a561"
		logic_hash = "c275d0cfdadcaabe57c432956e96b4bb344d947899fa5ad55b872e02b4d44274"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "60a160abcbb6d93d9ee167663e419047f3297d549c534cbe66d035a0aa36d806"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "HOW_TO_RECOVER_FILES.txt"
		$a2 = "large_file_size_mb"
		$a3 = "note_text"

	condition:
		all of them
}