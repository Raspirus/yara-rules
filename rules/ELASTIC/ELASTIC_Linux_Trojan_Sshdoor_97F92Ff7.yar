rule ELASTIC_Linux_Trojan_Sshdoor_97F92Ff7 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Sshdoor (Linux.Trojan.Sshdoor)"
		author = "Elastic Security"
		id = "97f92ff7-b14f-4cdf-aef7-d1ca3e46ae48"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Sshdoor.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2e1d909e4a6ba843194f9912826728bd2639b0f34ee512e0c3c9e5ce4d27828e"
		logic_hash = "a883c790fd7fdeb0ca6de5fcf4dd69a996b6d85db3179a8a28adbbbc1dc01bc6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4ad5b6b259655bf1bf58d662cf3daf3fec6ba61fcff36e24e8d239e99a8bd36f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C0 75 C3 48 8B 44 24 08 64 48 33 04 25 28 00 00 00 75 07 48 83 }

	condition:
		all of them
}