
rule ELASTIC_Macos_Trojan_Bundlore_28B13E67 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
		author = "Elastic Security"
		id = "28b13e67-e01c-45eb-aae6-ecd02b017a44"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Bundlore.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0b50a38749ea8faf571169ebcfce3dfd668eaefeb9a91d25a96e6b3881e4a3e8"
		logic_hash = "586ae19e570c51805afd3727b2e570cdb1c48344aa699e54774a708f02bc3a6f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1e85be4432b87214d61e675174f117e36baa8ab949701ee1d980ad5dd8454bac"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 05 A5 A3 A9 37 D2 05 13 E9 3E D6 EA 6A EC 9B DC 36 E5 76 A7 53 B3 0F 06 46 D1 }

	condition:
		all of them
}