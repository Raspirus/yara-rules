rule ELASTIC_Linux_Trojan_Gafgyt_0535Ebf7 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "0535ebf7-844f-4207-82ef-e155ceff7a3e"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1367-L1385"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "77e18bb5479b644ba01d074057c9e2bd532717f6ab3bb88ad2b7497b85d2a5de"
		logic_hash = "eb574468e9d371def0da74e6aba827272181399a84388a14ffb167ec6ebd40d1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2b9b17dad296c0a58a7efa1fb3f71c62bf849f00deb978c1103ab8a480290024"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F8 48 8B 04 24 6A 18 48 F7 14 24 48 FF 04 24 48 03 24 24 48 8D 64 }

	condition:
		all of them
}