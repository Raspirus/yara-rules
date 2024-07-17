rule ELASTIC_Linux_Trojan_Winnti_61215D98 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Winnti (Linux.Trojan.Winnti)"
		author = "Elastic Security"
		id = "61215d98-f52d-45d3-afa2-4bd25270aa99"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Winnti.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "cc1455e3a479602581c1c7dc86a0e02605a3c14916b86817960397d5a2f41c31"
		logic_hash = "051cc157f189094d25d45e66e410bdfd61ed7649a4c935d076cec1597c5debf5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "20ee92147edbf91447cca2ee0c47768a50ec9c7aa7d081698953d3bdc2a25320"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FF FF FF C9 C3 55 48 89 E5 48 83 EC 30 89 F8 66 89 45 DC C7 45 FC FF FF }

	condition:
		all of them
}