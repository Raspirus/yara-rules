
rule ELASTIC_Linux_Trojan_Mech_D30Ec0A0 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mech (Linux.Trojan.Mech)"
		author = "Elastic Security"
		id = "d30ec0a0-3fd6-4d83-ad29-9d45704bc8ce"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mech.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "710d1a0a8c7eecc6d793933c8a97cec66d284b3687efee7655a2dc31d15c0593"
		logic_hash = "268aeb25d6468412d8123bab5eb2c8bd7704828d0ef3c3d771aa036e374127d7"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "061e9f1aade510132674d87ab5981e5b6b0ae3a2782a97d8cc6c2be7b26c6454"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 6E 63 20 2D 20 4C 69 6E 75 78 20 32 2E 32 2E 31 }

	condition:
		all of them
}