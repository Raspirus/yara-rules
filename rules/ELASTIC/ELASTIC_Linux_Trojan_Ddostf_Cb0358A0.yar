rule ELASTIC_Linux_Trojan_Ddostf_Cb0358A0 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ddostf (Linux.Trojan.Ddostf)"
		author = "Elastic Security"
		id = "cb0358a0-5303-4860-89ac-7dae037f5f0b"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ddostf.yar#L80-L98"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1015b9aef1f749dfc31eb33528c4a4169035b6d73542e068b617965d3e948ef2"
		logic_hash = "1f152b69bf0b2bfa539fdd42c432e456b9efb3766a450333a987313bb12c1826"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f97c96d457532f2af5fb0e1b40ad13dcfba2479c651266b4bdd1ab2a01c0360f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 66 C7 45 F2 00 00 8D 45 F2 8B 55 E4 0F B6 12 88 10 0F B7 45 F2 0F }

	condition:
		all of them
}