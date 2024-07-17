
rule ELASTIC_Linux_Trojan_Kinsing_85276Fb4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Kinsing (Linux.Trojan.Kinsing)"
		author = "Elastic Security"
		id = "85276fb4-11f4-4265-9533-a96b42247f96"
		date = "2021-12-13"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Kinsing.yar#L60-L78"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b3527e3d03a30fcf1fdaa73a1b3743866da6db088fbfa5f51964f519e22d05e6"
		logic_hash = "6919afd133e7e369eece10ea79d9d17a1a3fbb6210593395e0be157f8c262811"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "966d53d8fc0e241250a861107317266ad87205d25466a4e6cdb27c3e4e613d92"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 65 5F 76 00 64 48 8B 0C 25 F8 FF FF FF 48 3B 61 10 76 38 48 83 }

	condition:
		all of them
}