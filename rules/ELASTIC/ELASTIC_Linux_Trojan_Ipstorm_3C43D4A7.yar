
rule ELASTIC_Linux_Trojan_Ipstorm_3C43D4A7 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ipstorm (Linux.Trojan.Ipstorm)"
		author = "Elastic Security"
		id = "3c43d4a7-185a-468b-a73d-82f579de98c1"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ipstorm.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5103133574615fb49f6a94607540644689be017740d17005bc08b26be9485aa7"
		logic_hash = "c7e9191312197f8925d7231d0b8badf8b5ca35685df909c0d1feb301b4385d7b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "cf6812f8f0ee7951a70bec3839b798a574d536baae4cf37cda6eebf570cab0be"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 48 8D 54 24 58 31 F6 EB 11 48 8B 84 24 88 00 00 00 48 89 F1 48 }

	condition:
		all of them
}