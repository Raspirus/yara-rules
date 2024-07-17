
rule ELASTIC_Linux_Cryptominer_Camelot_B25398Dd : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Camelot (Linux.Cryptominer.Camelot)"
		author = "Elastic Security"
		id = "b25398dd-33cc-4ad8-b943-cd06ff7811fb"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Camelot.yar#L39-L57"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6fb3b77be0a66a10124a82f9ec6ad22247d7865a4d26aa49c5d602320318ce3c"
		logic_hash = "e7fdb3c573909e8f197417278a6d333cc3743b05257d81fed46769b185354183"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6bdcefe93b1c36848b79cdc6b2ff79deb04012a030e5d92e725c87e520c15554"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 04 76 48 8B 44 07 23 48 33 82 C0 00 00 00 48 89 44 24 50 49 8B }

	condition:
		all of them
}