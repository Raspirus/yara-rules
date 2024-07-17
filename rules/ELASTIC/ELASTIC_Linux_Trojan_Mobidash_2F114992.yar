rule ELASTIC_Linux_Trojan_Mobidash_2F114992 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mobidash (Linux.Trojan.Mobidash)"
		author = "Elastic Security"
		id = "2f114992-36a7-430c-8bd9-5661814d95a8"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mobidash.yar#L237-L255"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
		logic_hash = "f93fe72e08c8ec135cccc8cdab2ecedbb694e9ad39f2572d060864bb3290e25c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2371fc5ba1e279a77496328d3a39342408609f04f1a8947e84e734d28d874416"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { DF 4C 89 F6 48 8B 80 B8 00 00 00 48 8D 64 24 58 5B 5D 41 5C }

	condition:
		all of them
}