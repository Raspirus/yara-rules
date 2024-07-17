
rule ELASTIC_Linux_Trojan_Gafgyt_F51C5Ac3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "f51c5ac3-ade9-4d01-b578-3473a2b116db"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L594-L612"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
		logic_hash = "e82b5ddb760d5bdcd146e1de12ec34c4764e668543420765146e22dee6f5732b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "34f254afdf94b1eb29bae4eb8e3864ea49e918a5dbe6e4c9d06a4292c104a792"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 74 2A 8B 45 0C 0F B6 00 84 C0 74 17 8B 45 0C 40 89 44 24 04 8B }

	condition:
		all of them
}