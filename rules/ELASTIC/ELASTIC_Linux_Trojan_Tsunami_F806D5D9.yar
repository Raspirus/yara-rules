
rule ELASTIC_Linux_Trojan_Tsunami_F806D5D9 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "f806d5d9-0bf6-4da7-80fb-b1612f2ddd5b"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5259495788f730a2a3bad7478c1873c8a6296506a778f18bc68e39ce48b979da"
		logic_hash = "86336f662e3abcf2fe7635155782c549fc9eef514356bf78bfbc3b65192e2d90"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "f4f838fcd1fe7f85e435225f3e34b77b848246b2b9618b47125a611c8d282347"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 41 54 45 48 54 54 50 20 3C 68 6F 73 74 3E 20 3C 73 72 63 3A }

	condition:
		all of them
}