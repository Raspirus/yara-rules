
rule ELASTIC_Linux_Trojan_Generic_402Be6C5 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Generic (Linux.Trojan.Generic)"
		author = "Elastic Security"
		id = "402be6c5-a1d8-4d7a-88ba-b852e0db1098"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Generic.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d30a8f5971763831f92d9a6dd4720f52a1638054672a74fdb59357ae1c9e6deb"
		logic_hash = "b32111972bc21822f0f2c8e47198c90b70e78667410175257b9542c212fc3a1d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1e906f5a06f688084edf537ead0b7e887bd9e0fcc39990c976ea8c136dc52624"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C0 52 4C 95 42 11 01 64 E9 D7 39 E4 89 34 FA 48 01 02 C1 3B 39 }

	condition:
		all of them
}