
rule ELASTIC_Linux_Trojan_Gafgyt_807911A2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "807911a2-f6ec-4e65-924f-61cb065dafc6"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L238-L255"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "66b15304d5ed22daea666bd0e2b18726b8a058361ff8d69b974bfded933a4d8c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f409037091b7372f5a42bbe437316bd11c655e7a5fe1fcf83d1981cb5c4a389f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FE 48 39 F3 0F 94 C2 48 83 F9 FF 0F 94 C0 84 D0 74 16 4B 8D }

	condition:
		all of them
}