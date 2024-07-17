
rule ELASTIC_Linux_Trojan_Gafgyt_Eaa9A668 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "eaa9a668-e3b9-4657-81bf-1c6456e2053a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L554-L572"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "409c55110d392aed1a9ec98a6598fb8da86ab415534c8754aa48e3949e7c4b62"
		logic_hash = "05e9047342a9d081a09f8514f0ec32d72bc43a286035014ada90b0243f92cfa8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bee2744457164e5747575a101026c7862474154d82f52151ac0d77fb278d9405"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 C0 0F B6 00 3C 2F 76 0B 48 8B 45 C0 0F B6 00 3C 39 76 C7 48 8B }

	condition:
		all of them
}