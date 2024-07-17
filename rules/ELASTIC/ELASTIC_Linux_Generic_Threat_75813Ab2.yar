rule ELASTIC_Linux_Generic_Threat_75813Ab2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "75813ab2-47f5-40ad-b512-9aa081abdc03"
		date = "2024-02-01"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L530-L549"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5819eb73254fd2a698eb71bd738cf3df7beb65e8fb5e866151e8135865e3fd9a"
		logic_hash = "06e5daed278273137e416ef3ee6ac8496b144a9c3ce213ec92881ba61d7db6cb"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "e5b985f588cf6d1580b8e5dc85350fd0e1ca22ca810b1eca8d2bed774237c930"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 5B 2B 5D 20 6D 6D 61 70 3A 20 30 78 25 6C 78 20 2E 2E 20 30 78 25 6C 78 }
		$a2 = { 5B 2B 5D 20 70 61 67 65 3A 20 30 78 25 6C 78 }

	condition:
		all of them
}