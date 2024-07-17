rule ELASTIC_Linux_Trojan_Gafgyt_30444846 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "30444846-439f-41e1-b0b4-c12da774a228"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L455-L473"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c84b81d79d437bb9b8a6bad3646aef646f2a8e1f1554501139648d2f9de561da"
		logic_hash = "26bc95efb2ea69fece52cf3ab38ce35891c77fc0dac3e26e5580ba3a88e112e9"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "3c74db508de7c8c1c190d5569e0a2c2b806f72045e7b74d44bfbaed20ecb956b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 64 20 2B 78 20 74 66 74 70 31 2E 73 68 3B 20 73 68 20 74 66 74 }

	condition:
		all of them
}