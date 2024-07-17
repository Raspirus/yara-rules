rule ELASTIC_Linux_Trojan_Swrort_5Ad1A4F9 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Swrort (Linux.Trojan.Swrort)"
		author = "Elastic Security"
		id = "5ad1a4f9-bfe5-4e5f-94e9-4983c93a1c1f"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Swrort.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fa5695c355a6dc1f368a4b36a45e8f18958dacdbe0eac80c618fbec976bac8fe"
		logic_hash = "3a1fa978e0c8ab0dd4e7965a3f91306d6123c19f21b86d3f8088979bf58c3a07"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a91458dd4bcd082506c554ca8479e1b0d23598e0e9a0e44ae1afb2651ce38dce"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 53 57 68 B7 E9 38 FF FF D5 53 53 57 68 74 EC 3B E1 FF D5 57 }

	condition:
		all of them
}