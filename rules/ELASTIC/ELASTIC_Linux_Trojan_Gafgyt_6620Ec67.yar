
rule ELASTIC_Linux_Trojan_Gafgyt_6620Ec67 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "6620ec67-8f12-435b-963c-b44a02f43ef1"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L634-L652"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b91eb196605c155c98f824abf8afe122f113d1fed254074117652f93d0c9d6b2"
		logic_hash = "2df2c8cdc2cb545f916159d44a800708b55a2993cd54a4dcf920a6a8dc6361e7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9d68db5b3779bb5abe078f9e36dd9a09d4d3ad9274a3a50bdfa0e444a7e46623"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { AF 93 64 1A D8 0B 48 93 64 0B 48 A3 64 11 D1 0B 41 05 E4 48 }

	condition:
		all of them
}