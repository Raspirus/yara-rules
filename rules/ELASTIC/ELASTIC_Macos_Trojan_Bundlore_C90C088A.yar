rule ELASTIC_Macos_Trojan_Bundlore_C90C088A : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
		author = "Elastic Security"
		id = "c90c088a-abf5-4e52-a69e-5a4fd4b5cf15"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Bundlore.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "875513f4ebeb63b9e4d82fb5bff2b2dc75b69c0bfa5dd8d2895f22eaa783f372"
		logic_hash = "c82c5c8d1e38e0d2631c5611e384eb49b58c64daeafe0cc642682e5c64686b60"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c2300895f8ff5ae13bc0ed93653afc69b30d1d01f5ce882bd20f2b65426ecb47"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 35 E1 11 00 00 92 80 35 DB 11 00 00 2A 80 35 D5 11 00 00 7F 80 35 CF 11 00 00 }

	condition:
		all of them
}