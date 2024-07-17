
rule ELASTIC_Linux_Cryptominer_Xmrminer_98B00F9C : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrminer (Linux.Cryptominer.Xmrminer)"
		author = "Elastic Security"
		id = "98b00f9c-354a-47dd-8546-a2842559d247"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrminer.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c01b88c5d3df7ce828e567bd8d639b135c48106e388cd81497fcbd5dcf30f332"
		logic_hash = "cf8c5deddf22e7699cd880bd3f9f28721db5ece6705be4f932e1d041893eef71"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8d231a490e818614141d6805a9e7328dc4b116b34fd027d5806043628b347141"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0F 38 DC DF 49 89 D4 66 0F 7F 24 1A 66 0F EF C3 66 42 0F 7F }

	condition:
		all of them
}