
rule ELASTIC_Linux_Trojan_Gafgyt_A0A4De11 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "a0a4de11-fe65-449f-a990-ad5f18ac66f0"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L415-L433"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "cf1ca1d824c8687e87a5b0275a0e39fa101442b4bbf470859ddda9982f9b3417"
		logic_hash = "220c6ba82b906f070123b3bae9aafa72c0fb3bc8d5858a4f4bd65567076eb73d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "891cfc6a4c38fb257ada29050e0047bd1301e8f0a6a1a919685b1fcc2960b047"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 42 0D 83 C8 10 88 42 0D 48 8B 55 D8 0F B6 42 0D 83 C8 08 88 }

	condition:
		all of them
}