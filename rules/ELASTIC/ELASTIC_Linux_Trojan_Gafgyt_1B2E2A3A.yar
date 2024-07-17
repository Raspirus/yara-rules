rule ELASTIC_Linux_Trojan_Gafgyt_1B2E2A3A : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "1b2e2a3a-1302-41c7-be99-43edb5563294"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L832-L850"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
		logic_hash = "6f40f868d20f0125721eb2a7934b356d69b695d4a558155a2ddcd0107d3f8c30"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6f24b67d0a6a4fc4e1cfea5a5414b82af1332a3e6074eb2178aee6b27702b407"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 83 7D 18 00 74 25 8B 45 1C 83 E0 02 85 C0 74 1B C7 44 24 04 2D 00 }

	condition:
		all of them
}