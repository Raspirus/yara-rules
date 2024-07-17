
rule ELASTIC_Macos_Trojan_Bundlore_00D9D0E9 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
		author = "Elastic Security"
		id = "00d9d0e9-28d8-4c32-bc6f-52008ee69b07"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Bundlore.yar#L101-L119"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "73069b34e513ff1b742b03fed427dc947c22681f30cf46288a08ca545fc7d7dd"
		logic_hash = "535831872408caa27984190d1b1b1a5954e502265925d50457e934219598dbfd"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7dcc6b124d631767c259101f36b4bbd6b9d27b2da474d90e31447ea03a2711a6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 35 8E 11 00 00 55 80 35 88 11 00 00 BC 80 35 82 11 00 00 72 80 35 7C 11 00 00 }

	condition:
		all of them
}