
rule ELASTIC_Linux_Trojan_Gafgyt_656Bf077 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "656bf077-ca0c-4d28-9daa-eb6baafaf467"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L712-L730"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c5a317d0d8470814ff343ce78ad2428ebb3f036763fcf703a589b6c4d33a3ec6"
		logic_hash = "0c9728304e720eb2cd00afad8d16f309514473dece48fa94af6a72ca41705a36"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3ea8ed60190198d5887bb7093975d648a9fd78234827d648a8258008c965b1c1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 74 28 48 8B 45 E8 0F B6 00 84 C0 74 14 48 8B 75 E8 48 FF C6 48 8B }

	condition:
		all of them
}