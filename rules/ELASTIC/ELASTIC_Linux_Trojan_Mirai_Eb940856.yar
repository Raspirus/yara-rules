rule ELASTIC_Linux_Trojan_Mirai_Eb940856 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "eb940856-60d2-4148-9126-aac79a24828e"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1942-L1960"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fbf814c04234fc95b6a288b62fb9513d6bbad2e601b96db14bb65ab153e65fef"
		logic_hash = "d7bb2373a35ea97a11513e80e9a561f53a8f0b9345f392e8e7f042d4cb2d7d20"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "01532c6feda3487829ad005232d30fe7dde5e37fd7cecd2bb9586206554c90a7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 84 24 80 00 00 00 31 C9 EB 23 48 89 4C 24 38 48 8D 84 24 C8 00 }

	condition:
		all of them
}