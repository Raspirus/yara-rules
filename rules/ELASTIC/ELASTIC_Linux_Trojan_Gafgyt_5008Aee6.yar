
rule ELASTIC_Linux_Trojan_Gafgyt_5008Aee6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "5008aee6-3866-4f0a-89bf-bde740baee5c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L60-L78"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b32cd71fcfda0a2fcddad49d8c5ba8d4d68867b2ff2cb3b49d1a0e358346620c"
		logic_hash = "538bae17dcf0298e379f656e1dba794b75af6c7448a23253a51994bde9d30524"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6876a6c1333993c4349e459d4d13c11be1b0f78311274c0f778e65d0fabeeaa7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 50 16 B4 87 58 83 00 21 84 51 FD 13 4E 79 28 57 C3 8B 30 55 }

	condition:
		all of them
}