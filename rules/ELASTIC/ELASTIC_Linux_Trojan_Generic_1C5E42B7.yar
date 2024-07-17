
rule ELASTIC_Linux_Trojan_Generic_1C5E42B7 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Generic (Linux.Trojan.Generic)"
		author = "Elastic Security"
		id = "1c5e42b7-b873-443e-a30c-66a75fc39b21"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Generic.yar#L161-L179"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b078a02963610475217682e6e1d6ae0b30935273ed98743e47cc2553fbfd068f"
		logic_hash = "cd759b87a303fafb9461d0a73b6a6b3f468b1f3db0189ba0e584a629e5d78da1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b64284e1220ec9abc9b233e513020f8b486c76f91e4c3f2a0a6fb003330c2535"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 C0 89 45 F4 83 7D F4 FF 75 1C 83 EC 0C 68 }

	condition:
		all of them
}