
rule ELASTIC_Linux_Trojan_Ircbot_7C60454D : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ircbot (Linux.Trojan.Ircbot)"
		author = "Elastic Security"
		id = "7c60454d-8290-4e91-9b0a-2392aebe1bec"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ircbot.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "14eeff3516de6d2cb11d6ada4026e3dcee1402940e3a0fb4fa224a5c030049d8"
		logic_hash = "90dcd0a3d3f6345e66db0a4f8465e3830eb4e3bcb675db16c60a89e20f935aec"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4f14dcca5704c2ef32caaed1c048a5fb14095f31be8630676c07cbc8b22e6c4d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 49 89 F0 41 54 55 48 89 CD 53 48 89 FB 48 83 EC 58 48 85 D2 }

	condition:
		all of them
}