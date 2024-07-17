
rule ELASTIC_Linux_Trojan_Mirai_01E4A728 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "01e4a728-7c1c-479b-aed0-cb76d64dbb02"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1145-L1162"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "753936b97a36c774975a1d0988f6f908d4b5e5906498aa34c606d4cd971f1ba5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d90477364982bdc6cd22079c245d866454475749f762620273091f2fab73c196"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 44 24 23 48 8B 6C 24 28 83 F9 01 4A 8D 14 20 0F B6 02 88 45 08 }

	condition:
		all of them
}