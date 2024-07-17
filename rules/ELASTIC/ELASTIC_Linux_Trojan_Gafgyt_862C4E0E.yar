rule ELASTIC_Linux_Trojan_Gafgyt_862C4E0E : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "862c4e0e-83a4-458b-8c00-f2f3cf0bf9db"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1030-L1048"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9526277255a8d632355bfe54d53154c9c54a4ab75e3ba24333c73ad0ed7cadb1"
		logic_hash = "a1dce44e76f9d2a517c4849c58dfecb07e1ef0d78fddff10af601184d636583f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2a6b4f8d8fb4703ed26bdcfbbb5c539dc451c8b90649bee80015c164eae4c281"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 02 89 45 F8 8B 45 F8 C1 E8 10 85 C0 75 E6 8B 45 F8 F7 D0 0F }

	condition:
		all of them
}