rule ELASTIC_Linux_Trojan_Meterpreter_383C6708 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Meterpreter (Linux.Trojan.Meterpreter)"
		author = "Elastic Security"
		id = "383c6708-0861-4089-93c3-4320bc1e7cfc"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Meterpreter.yar#L20-L38"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d9d607f0bbc101f7f6dc0f16328bdd8f6ddb8ae83107b7eee34e1cc02072cb15"
		logic_hash = "b0fd479722ab0808a4709cbacbb874282c48a425f4dbdaec9f74bc7f839c82e4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6e9da04c91b5846b3b1109f9d907d9afa917fb7dfe9f77780e745d17b799b540"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 99 B6 10 48 89 D6 4D 31 C9 6A 22 41 5A B2 07 0F 05 48 96 48 }

	condition:
		all of them
}