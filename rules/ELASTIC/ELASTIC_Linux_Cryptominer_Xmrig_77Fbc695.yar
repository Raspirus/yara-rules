rule ELASTIC_Linux_Cryptominer_Xmrig_77Fbc695 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrig (Linux.Cryptominer.Xmrig)"
		author = "Elastic Security"
		id = "77fbc695-6fe3-4e30-bb2f-f64379ec4efd"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrig.yar#L99-L117"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e723a2b976adddb01abb1101f2d3407b783067bec042a135b21b14d63bc18a68"
		logic_hash = "af8e09cd5d6b7532af0c06273aa465cf6c40ad6c919a679fd09191a1c2a302f5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e0c6cb7a05c622aa40dfe2167099c496b714a3db4e9b92001bbe6928c3774c85"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F2 0F 58 44 24 08 F2 0F 11 44 24 08 8B 7B 08 41 8D 76 01 49 83 }

	condition:
		all of them
}