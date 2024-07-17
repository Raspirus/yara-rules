
rule ELASTIC_Linux_Trojan_Mirai_4E2246Fb : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "4e2246fb-5f9a-4dea-8041-51758920d0b9"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1601-L1619"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1f6bcdfc7d1c56228897cd7548266bb0b9a41b913be354036816643ac21b6f66"
		logic_hash = "6d2e1300286751a5e1ae683e9aab2f59bfbb20d1cc18dcce89c06ecadf25a3e6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "23b0cfabc2db26153c02a7dc81e2006b28bfc9667526185b2071b34d2fb073c4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 00 B8 01 00 00 00 31 DB CD 80 EB FA 8D 8B 10 }

	condition:
		all of them
}