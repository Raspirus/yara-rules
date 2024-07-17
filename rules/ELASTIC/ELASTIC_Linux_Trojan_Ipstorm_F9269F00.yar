rule ELASTIC_Linux_Trojan_Ipstorm_F9269F00 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ipstorm (Linux.Trojan.Ipstorm)"
		author = "Elastic Security"
		id = "f9269f00-4664-47a4-9148-fa74e2cfee7c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ipstorm.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5103133574615fb49f6a94607540644689be017740d17005bc08b26be9485aa7"
		logic_hash = "5914d222b49aaf6c1040e48ffd93c04bd5df25f1d97bde79b034862fca6555f6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "509de41454bcc60dad0d96448592aa20fb997ce46ad8fed5d4bbdbe2ede588d6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { EC C0 00 00 00 48 89 AC 24 B8 00 00 00 48 8D AC 24 B8 00 00 00 B8 69 00 }

	condition:
		all of them
}