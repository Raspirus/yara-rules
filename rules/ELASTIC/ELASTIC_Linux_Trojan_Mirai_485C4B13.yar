
rule ELASTIC_Linux_Trojan_Mirai_485C4B13 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "485c4b13-3c7c-47a7-b926-8237cb759ad7"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L774-L792"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "49c94d184d7e387c3efe34ae6f021e011c3046ae631c9733ab0a230d5fe28ead"
		logic_hash = "9625e4190559cc77f41ebef24f9bfa5e3d2e2259c12b301148c614b0f98b5835"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "28f3e8982cee2836a59721c88ee0a9159ad6fdfc27c0091927f5286f3a731e9a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 7E 1F 8B 4C 24 4C 01 D1 0F B6 11 88 D0 2C 61 3C 19 77 05 80 }

	condition:
		all of them
}