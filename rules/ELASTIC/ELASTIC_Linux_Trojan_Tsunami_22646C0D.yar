
rule ELASTIC_Linux_Trojan_Tsunami_22646C0D : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "22646c0d-785c-4cf2-b8c8-289189ae14d0"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L340-L358"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "20439a8fc21a94c194888725fbbb7a7fbeef5faf4b0f704559d89f1cd2e57d9d"
		logic_hash = "548f531429132392f6d9bccff706b56ba87d8e44763116dedca5d0baa5097b92"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0b1dce4e74536d4d06430aefd0127c740574dcc9a0e5ada42f3d51d97437720f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { CB 01 00 00 55 53 51 52 48 01 FE 56 48 89 FE 48 89 D7 31 DB }

	condition:
		all of them
}