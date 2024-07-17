rule ELASTIC_Windows_Trojan_Trickbot_D916Ae65 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "d916ae65-c97b-495c-89c2-4f1ec90081d2"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L269-L286"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "e0aafe498cd9f0e8addfef78027943a754ca797aafae0cb40f1c6425de501339"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2e109ed59a1e759ef089e04c21016482bf70228da30d8b350fc370b4e4d120e0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 5F 24 01 10 CF 22 01 10 EC 22 01 10 38 23 01 10 79 23 01 10 82 }

	condition:
		all of them
}