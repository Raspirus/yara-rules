rule ELASTIC_Linux_Trojan_Ircbot_Bb204B81 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ircbot (Linux.Trojan.Ircbot)"
		author = "Elastic Security"
		id = "bb204b81-db58-434f-b834-672cdc25e56c"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ircbot.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6147481d083c707dc98905a1286827a6e7009e08490e7d7c280ed5a6356527ad"
		logic_hash = "90d211c11281f5f8832210f3fc087fe5ff5a519b9b38628835e8b5fcc560bd9b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "66f9a8a31653a5e480f427d2d6a25b934c2c53752308eedb57eaa7b7cb7dde2e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0F 44 C8 4C 5E F8 8D EF 80 83 CD FF 31 DB 30 22 }

	condition:
		all of them
}