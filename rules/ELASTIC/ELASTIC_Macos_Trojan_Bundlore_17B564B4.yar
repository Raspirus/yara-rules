rule ELASTIC_Macos_Trojan_Bundlore_17B564B4 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
		author = "Elastic Security"
		id = "17b564b4-7452-473f-873f-f907b5b8ebc4"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Bundlore.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "94f6e5ee6eb3a191faaf332ea948301bbb919f4ec6725b258e4f8e07b6a7881d"
		logic_hash = "40cd2a793c8ed51a8191ecb9b358f50dc2035d997d0f773f6049f9c272291607"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7701fab23d59b8c0db381a1140c4e350e2ce24b8114adbdbf3c382c6d82ea531"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 35 D9 11 00 00 05 80 35 D3 11 00 00 2B 80 35 CD 11 00 00 F6 80 35 C7 11 00 00 }

	condition:
		all of them
}