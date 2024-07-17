
rule ELASTIC_Linux_Trojan_Shark_B918Ab75 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Shark (Linux.Trojan.Shark)"
		author = "Elastic Security"
		id = "b918ab75-0701-4865-b798-521fdd2ffc28"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Shark.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8b6fe9f496996784e42b75fb42702aa47aefe32eac6f63dd16a0eb55358b6054"
		logic_hash = "16302c29f2ae4109b8679933eb7fd9ef9306b0c215f20e8fff992b0b848974a9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "15205d58af99b8eae14de2d5762fdc710ef682839967dd56f6d65bd3deaa7981"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 26 00 C7 46 14 0A 00 00 00 C7 46 18 15 00 00 00 EB 30 C7 46 14 04 00 }

	condition:
		all of them
}