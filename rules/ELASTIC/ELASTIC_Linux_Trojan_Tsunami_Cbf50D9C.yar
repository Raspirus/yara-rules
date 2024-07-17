rule ELASTIC_Linux_Trojan_Tsunami_Cbf50D9C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "cbf50d9c-2893-48c9-a2a9-45053f0a174b"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L420-L438"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b64d0cf4fc4149aa4f63900e61b6739e154d328ea1eb31f4c231016679fc4aa5"
		logic_hash = "331a35fb3ecc54022b1d4d05bd64e7c5c6a7997b06dbea3a36c33ccc0a2f7086"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "acb32177d07df40112d99ed0a2b7ed01fbca63df1f63387cf939caa4cf1cf83b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 07 F8 BF 81 9C B8 20 07 09 20 35 15 11 03 20 85 }

	condition:
		all of them
}