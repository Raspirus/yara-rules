rule ELASTIC_Linux_Trojan_Tsunami_8A11F9Be : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "8a11f9be-dc85-4695-9f38-80ca0304780e"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L201-L219"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1f773d0e00d40eecde9e3ab80438698923a2620036c2fc33315ef95229e98571"
		logic_hash = "f80dcb3579a76da787e9bb2bfb02ef86e464aec1bea405f02642b8c8902c7663"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "91e2572a3bb8583e20042578e95e1746501c6a71ef7635af2c982a05b18d7c6d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 3E 20 3C 70 6F 72 74 3E 20 3C 72 65 66 6C 65 63 74 69 6F 6E 20 }

	condition:
		all of them
}