
rule ELASTIC_Linux_Trojan_Gafgyt_620087B9 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "620087b9-c87d-4752-89e8-ca1c16486b28"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L852-L870"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
		logic_hash = "411451ea326498a25af8be5cd43fe0b98973af354706268c89828b88ece5e497"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "06cd7e6eb62352ec2ccb9ed48e58c0583c02fefd137cd048d053ab30b5330307"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 48 89 D8 48 83 C8 01 EB 04 48 8B 76 10 48 3B 46 08 72 F6 48 8B }

	condition:
		all of them
}