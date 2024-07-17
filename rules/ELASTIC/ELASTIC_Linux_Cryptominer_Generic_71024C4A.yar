rule ELASTIC_Linux_Cryptominer_Generic_71024C4A : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "71024c4a-e8da-44fc-9cf9-c71829dfe87a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L201-L219"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "afe81c84dcb693326ee207ccd8aeed6ed62603ad3c8d361e8d75035f6ce7c80f"
		logic_hash = "0c66a3388fe8546ae180e52d50ef05a28755d24e47b3b56f390d5c6fcb0b89eb"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dbbb74ec687e8e9293dfa2272d55b81ef863a50b0ff87daf15aaf6cee473efe6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 46 08 48 89 45 08 48 8B 46 10 48 85 C0 48 89 45 10 74 BC F0 FF }

	condition:
		all of them
}