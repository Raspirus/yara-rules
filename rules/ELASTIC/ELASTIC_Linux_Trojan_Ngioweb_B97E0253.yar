rule ELASTIC_Linux_Trojan_Ngioweb_B97E0253 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ngioweb (Linux.Trojan.Ngioweb)"
		author = "Elastic Security"
		id = "b97e0253-497f-4c2c-9d4c-ad89af64847f"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ngioweb.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5480bc02aeebd3062e6d19e50a5540536ce140d950327cce937ff7e71ebd15e2"
		logic_hash = "dc11d50166a4d1b400c0df81295054192d42822dd3e065e374a92a31727d4dbd"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "859f29acec8bb05b8a8e827af91e927db0b2390410179a0f5b03e7f71af64949"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 41 5C 41 5D 41 5E 41 5F C3 67 0F BE 17 39 F2 74 12 84 D2 74 04 }

	condition:
		all of them
}