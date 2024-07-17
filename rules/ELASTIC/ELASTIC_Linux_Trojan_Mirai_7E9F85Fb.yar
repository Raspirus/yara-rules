rule ELASTIC_Linux_Trojan_Mirai_7E9F85Fb : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "7e9f85fb-bfc4-4af6-9315-f6e43fefc4ff"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L438-L456"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4333e80fd311b28c948bab7fb3f5efb40adda766f1ea4bed96a8db5fe0d80ea1"
		logic_hash = "f4ce912e190bc5dcb56541f54ba8e47b6103c482bdc7e83b44693d2c066c0170"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ef420ec934e3fd07d5c154a727ed5c4689648eb9ccef494056fed1dea7aa5f9c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 85 50 FF FF FF 0F B6 40 04 3C 07 75 79 48 8B 85 50 FF FF FF }

	condition:
		all of them
}