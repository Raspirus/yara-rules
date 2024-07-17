rule ELASTIC_Linux_Trojan_Gognt_50C3D9Da : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gognt (Linux.Trojan.Gognt)"
		author = "Elastic Security"
		id = "50c3d9da-0392-4379-aafe-cfe63ade3314"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gognt.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "79602bc786edda7017c5f576814b683fba41e4cb4cf3f837e963c6d0d42c50ee"
		logic_hash = "ecd9cd94b3bf8c50c347e70aab3da03ea6589530b20941a9f62dac501f8144fc"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a4b7e0c7c2f1b0634f82106ec0625bcdde02296b3e72c9c3aa9c16e40d770b43"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 00 00 47 6F 00 00 51 76 46 5F 6F 30 59 36 55 72 5F 6C 63 44 }

	condition:
		all of them
}