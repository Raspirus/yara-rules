
rule ELASTIC_Linux_Trojan_Iroffer_711259E4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Iroffer (Linux.Trojan.Iroffer)"
		author = "Elastic Security"
		id = "711259e4-f081-4d81-8257-60ba733354c5"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Iroffer.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e76508141970efb3e4709bcff83772da9b10169c599e13e58432257a7bb2defa"
		logic_hash = "a71dbb979bc1f7671ab9958b6aa502e6ded4ee1c1b026080fd377eb772ebb1d5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "aca63ef57ab6cb5579a2a5fea6095d88a3a4fb8347353febb3d02cc88a241b78"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 03 7E 2B 8B 45 C8 3D FF 00 00 00 77 21 8B 55 CC 81 FA FF 00 }

	condition:
		all of them
}