rule ELASTIC_Linux_Trojan_Xhide_7F0A131B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xhide (Linux.Trojan.Xhide)"
		author = "Elastic Security"
		id = "7f0a131b-c305-4a08-91cc-ac2de4d95b19"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xhide.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0dc35f1a1fe1c59e454cd5645f3a6220b7d85661437253a3e627eed04eca2560"
		logic_hash = "4843042576d1f4f37b5a7cda1b261831030d9145c49b57e9b4c66e2658cc8cf9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "767f2ea258cccc9f9b6673219d83e74da1d59f6847161791c9be04845f17d8cb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 8B 85 68 FF FF FF 83 E0 40 85 C0 75 1A 8B 85 68 FF FF FF 83 }

	condition:
		all of them
}