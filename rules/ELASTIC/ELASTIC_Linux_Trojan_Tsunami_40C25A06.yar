
rule ELASTIC_Linux_Trojan_Tsunami_40C25A06 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "40c25a06-5f3c-42c1-9a8c-5c4a1568ff9a"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L440-L458"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "61af6bb7be25465e7d469953763be5671f33c197d4b005e4a78227da11ae91e9"
		logic_hash = "38976911ff9e56fae27fad8b9df01063ed703f43c8220b1fbcef7a3945b3f1ad"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b45d666e2e7d571e95806a1a2c8e01cd5cd0d71160cbb06b268110d459ee252d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 20 74 13 9C B8 20 07 09 20 35 15 11 03 20 85 }

	condition:
		all of them
}