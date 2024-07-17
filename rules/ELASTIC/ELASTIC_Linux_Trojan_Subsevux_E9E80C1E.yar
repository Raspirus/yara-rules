rule ELASTIC_Linux_Trojan_Subsevux_E9E80C1E : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Subsevux (Linux.Trojan.Subsevux)"
		author = "Elastic Security"
		id = "e9e80c1e-c064-47cf-91f2-0561dd5c9bcd"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Subsevux.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a4ccd399ea99d4e31fbf2bbf8017c5368d29e630dc2985e90f07c10c980fa084"
		logic_hash = "8bc38f26da5a3350cbae3e93b890220bb461ff77e83993a842f68db8f757e435"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bbd7a2d80e545d0cae7705a53600f6b729918a3d655bc86b2db83f15d4e550e3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 C0 89 45 F4 83 7D F4 00 79 1C 83 EC 0C 68 }

	condition:
		all of them
}