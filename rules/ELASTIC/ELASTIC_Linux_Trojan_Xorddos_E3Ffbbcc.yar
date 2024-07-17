rule ELASTIC_Linux_Trojan_Xorddos_E3Ffbbcc : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "e3ffbbcc-7751-4d96-abec-22dd9618cab1"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L197-L215"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "28b7ddf2548411910af033b41982cdc74efd8a6ef059a54fda1b6cbd59faa8f6"
		logic_hash = "54711c2d3e6d73cf4358ba4a65cb19d996adcfa905c0089a18a61fe841fe9a34"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d5d5117a31da1a0ac3ef4043092eed47e2844938da9d03e2b68a66658e300175"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FF 10 52 FB FF D0 52 FB FF 00 52 FB FF D0 52 FB FF F0 51 FB }

	condition:
		all of them
}