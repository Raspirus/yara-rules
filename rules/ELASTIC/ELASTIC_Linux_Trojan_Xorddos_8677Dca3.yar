rule ELASTIC_Linux_Trojan_Xorddos_8677Dca3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "8677dca3-e36b-439f-bc55-76d951114020"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L417-L435"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "23813dc4aa56683e1426e5823adc3aab854469c9c0f3ec1a3fad40fa906929f2"
		logic_hash = "9902758dfb61e8b60b281f3f51cda8a10d58eb0cc20743f97998d7bcf120c299"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4d276b225f412b3879db19546c09d1dea2ee417c61ab6942c411bc392fee8e26"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F2 5E 83 C2 03 8B FF C1 E2 05 9C 83 C5 69 9D 8D 6D 97 03 C2 56 8B 74 }

	condition:
		all of them
}