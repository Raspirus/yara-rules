rule ELASTIC_Linux_Trojan_Tsunami_71D31510 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "71d31510-cd2c-4b61-b2cf-975d5ed70c93"
		date = "2021-12-13"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L500-L518"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "33dd6c0af99455a0ca3908c0117e16a513b39fabbf9c52ba24c7b09226ad8626"
		logic_hash = "18bfe9347faf1811686a61e0ee0de5cef842beb25fb06793947309135c41de89"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6c9f3f31e9dcdcd4b414e79e06f0ae633e50ef3e19a437c1b964b40cc74a57cb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 5C B3 C0 19 17 5E 7B 8B 22 16 17 E0 DE 6E 21 46 FB DD 17 67 }

	condition:
		all of them
}