
rule ELASTIC_Linux_Trojan_Connectback_Bf194C93 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Connectback (Linux.Trojan.Connectback)"
		author = "Elastic Security"
		id = "bf194c93-92d8-4eba-99c4-326a5ea76d0d"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Connectback.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6784cb86460bddf1226f71f5f5361463cbda487f813d19cd88e8a4a1eb1a417b"
		logic_hash = "148626e05caee4a2b2542726ea4e4dab074eeab0572a65fdbd32f5d96544daf8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6e72b14be0a0a6e42813fa82ee77d057246ccba4774897b38acf2dc30c894023"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { B6 0C B0 03 CD 80 85 C0 78 02 FF E1 B8 01 00 00 00 BB 01 00 }

	condition:
		all of them
}