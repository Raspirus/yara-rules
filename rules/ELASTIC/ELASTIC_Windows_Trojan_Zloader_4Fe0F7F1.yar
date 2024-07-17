
rule ELASTIC_Windows_Trojan_Zloader_4Fe0F7F1 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Zloader (Windows.Trojan.Zloader)"
		author = "Elastic Security"
		id = "4fe0f7f1-93c6-4397-acd5-1557608efaf4"
		date = "2022-03-03"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Zloader.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "161e657587361b29cdb883a6836566a946d9d3e5175e166a9fe54981d0c667fa"
		logic_hash = "b20fafc9db08c7668b49e18f45632594c3a69ec65fe865e79379c544fc424f8d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f340f41cc69930d24ffdae484d1080cd9ce5cb5e7720868c956923a5b8e6c9b1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 08 8B 75 F0 85 DB 8D 7D 94 89 45 E8 0F 45 FB 31 DB 85 F6 0F }

	condition:
		all of them
}