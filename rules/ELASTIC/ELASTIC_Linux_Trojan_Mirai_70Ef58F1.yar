
rule ELASTIC_Linux_Trojan_Mirai_70Ef58F1 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "70ef58f1-ac74-4e33-ae03-e68d1d5a4379"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L378-L396"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
		logic_hash = "3ad201d643e8f93a6f9075c03a76020d78186702a19bf9174b08688a2e94ef5c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c46eac9185e5f396456004d1e0c42b54a9318e0450f797c55703122cfb8fea89"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 D0 8B 19 01 D8 0F B6 5C 24 10 30 18 89 D0 8B 19 01 D8 0F B6 5C }

	condition:
		all of them
}