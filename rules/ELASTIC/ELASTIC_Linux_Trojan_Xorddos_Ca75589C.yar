rule ELASTIC_Linux_Trojan_Xorddos_Ca75589C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "ca75589c-6354-411b-b0a5-8400e657f956"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L237-L255"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0448c1b2c7c738404ba11ff4b38cdc8f865ccf1e202f6711345da53ce46e7e16"
		logic_hash = "c717e6f85a5b30514803ba43c85d82e2aaa4533b7f74db5345df83d1cc4c6551"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0bcaeae9ec0f5de241a05c77aadb5c3f2e39c84d03236971a0640ebae528a496"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 6D E0 25 01 00 00 00 55 8B EC C9 87 D1 87 0C 24 87 D1 8D 64 }

	condition:
		all of them
}