
rule ELASTIC_Linux_Trojan_Gafgyt_9Abf7E0C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "9abf7e0c-5076-4881-a488-f0f62810f843"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1109-L1126"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "00276330e388d07368577c4134343cb9fc11957dba6cff5523331199f1ed04aa"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7d02513aaef250091a58db58435a1381974e55c2ed695c194b6b7b83c235f848"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 55 E0 0F B6 42 0D 83 C8 01 88 42 0D 48 8B 55 E0 0F B6 42 0D 83 }

	condition:
		all of them
}