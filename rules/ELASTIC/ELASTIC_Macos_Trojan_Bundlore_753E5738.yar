rule ELASTIC_Macos_Trojan_Bundlore_753E5738 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
		author = "Elastic Security"
		id = "753e5738-0c72-4178-9396-d1950e868104"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Bundlore.yar#L181-L199"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "42aeea232b28724d1fa6e30b1aeb8f8b8c22e1bc8afd1bbb4f90e445e31bdfe9"
		logic_hash = "7a6907b51c793e4182c1606eab6f2bcb71f0350a34aef93fa3f3a9f1a49961ba"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c0a41a8bc7fbf994d3f5a5d6c836db3596b1401b0e209a081354af2190fcb3c2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 35 9A 11 00 00 96 80 35 94 11 00 00 68 80 35 8E 11 00 00 38 80 35 88 11 00 00 }

	condition:
		all of them
}