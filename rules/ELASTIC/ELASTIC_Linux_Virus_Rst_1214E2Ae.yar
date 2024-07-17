rule ELASTIC_Linux_Virus_Rst_1214E2Ae : FILE MEMORY
{
	meta:
		description = "Detects Linux Virus Rst (Linux.Virus.Rst)"
		author = "Elastic Security"
		id = "1214e2ae-90e4-425e-b47f-0a0981623236"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Virus_Rst.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b0e4f44d2456960bb6b20cb468c4ca1390338b83774b7af783c3d03e49eebe44"
		logic_hash = "82de4a97f414d591daba2d5d49b941ec4c51d6a6af36f97f062eaac5c74ebe30"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a13a9825815a417be991db57f80dac4d0c541e303e4a4e6bd03c46ece73703ea"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 00 00 53 89 F3 CD 80 5B 58 5F 5E 5A 59 5B C3 }

	condition:
		all of them
}