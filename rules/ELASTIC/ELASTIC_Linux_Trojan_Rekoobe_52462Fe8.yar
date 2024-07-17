rule ELASTIC_Linux_Trojan_Rekoobe_52462Fe8 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Rekoobe (Linux.Trojan.Rekoobe)"
		author = "Elastic Security"
		id = "52462fe8-a40c-4620-b539-d0c1f9d2ceee"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Rekoobe.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c1d8c64105caecbd90c6e19cf89301a4dc091c44ab108e780bdc8791a94caaad"
		logic_hash = "1ab6979392eeaa7bd6bd84f8d3531bd9071c54b58306a42dcfdd27bf7ec8f8cd"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e09e8e023b3142610844bf7783c5472a32f63c77f9a46edc028e860da63e6eeb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 1C D8 48 8B 5A E8 4A 33 0C DE 48 89 4A E0 89 D9 C1 E9 18 48 8B }

	condition:
		all of them
}