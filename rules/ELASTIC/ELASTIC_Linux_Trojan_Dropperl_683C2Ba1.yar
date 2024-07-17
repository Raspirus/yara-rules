
rule ELASTIC_Linux_Trojan_Dropperl_683C2Ba1 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Dropperl (Linux.Trojan.Dropperl)"
		author = "Elastic Security"
		id = "683c2ba1-fe4a-44e4-b176-8d5d5788e1a4"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Dropperl.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a02e166fbf002dd4217c012f24bb3a8dbe310a9f0b0635eb20a7d315049367e1"
		logic_hash = "eef2bdef7e20633f7dc92f653b43e3a217e8cbdbac63d05540bdd520e22dd1ed"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "42dcea472417140d0f7768e8189ac3a8a46aaeff039be1efd36f8d50f81e347c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E8 95 FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }

	condition:
		all of them
}