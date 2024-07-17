
rule ELASTIC_Macos_Trojan_Bundlore_Cb7344Eb : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
		author = "Elastic Security"
		id = "cb7344eb-51e6-4f17-a5d4-eea98938945b"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Bundlore.yar#L161-L179"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "53373668d8c5dc17f58768bf59fb5ab6d261a62d0950037f0605f289102e3e56"
		logic_hash = "6b5e868dfd14e9b1cdf3caeb1216764361b28c1dd38849526baf5dbdb1020d8d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6041c50c9eefe9cafb8768141cd7692540f6af2cdd6e0a763b7d7e50b8586999"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 35 ED 09 00 00 92 80 35 E7 09 00 00 93 80 35 E1 09 00 00 16 80 35 DB 09 00 00 }

	condition:
		all of them
}