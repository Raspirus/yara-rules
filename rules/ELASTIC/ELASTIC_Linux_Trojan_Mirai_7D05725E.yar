rule ELASTIC_Linux_Trojan_Mirai_7D05725E : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "7d05725e-db59-42a7-99aa-99de79728126"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L871-L889"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
		logic_hash = "ac2d0b81325ce7984bc09f93e61b42c8e312a31c75f09d37313d70cd40d3cf8b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7fcd34cb7c37836a1fa8eb9375a80da01bda0e98c568422255d83c840acc0714"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 97 00 00 00 89 6C 24 08 89 74 24 04 89 14 24 0F B7 C0 89 44 }

	condition:
		all of them
}