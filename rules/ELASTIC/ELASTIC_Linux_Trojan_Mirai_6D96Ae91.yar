
rule ELASTIC_Linux_Trojan_Mirai_6D96Ae91 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "6d96ae91-9d5c-48f1-928b-1562b120a74d"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L557-L575"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e3a1d92df6fb566e09c389cfb085126d2ea0f51a776ec099afb8913ef5e96f9b"
		logic_hash = "43b0ac7090620eb6c892f1105778c395bf18f5ac309ce1b2d9015b5abccbfc2a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fdbeaae0a96f3950d19aed497fae3e7a5517db141f53a1a6315b38b1d53d678b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 01 00 00 C1 00 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D }

	condition:
		all of them
}