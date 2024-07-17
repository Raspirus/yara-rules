rule ELASTIC_Linux_Trojan_Tsunami_6B3974B2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "6b3974b2-fd7f-4ebf-8aba-217761e7b846"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L281-L299"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2216776ba5c6495d86a13f6a3ce61b655b72a328ca05b3678d1abb7a20829d04"
		logic_hash = "7c44a0abcd51a6b775fc379b592652ebb10faf16c039ca23b20984183340cada"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "942a35f7acacf1d07577fe159a34dc7b04e5d07ff32ea13be975cfeea23e34be"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F4 89 45 EC 8B 45 EC C9 C3 55 89 E5 57 83 EC 0C EB 1F 8B 45 08 B9 FF FF }

	condition:
		all of them
}