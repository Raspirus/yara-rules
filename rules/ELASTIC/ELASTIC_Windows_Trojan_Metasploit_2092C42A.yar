
rule ELASTIC_Windows_Trojan_Metasploit_2092C42A : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Metasploit (Windows.Trojan.Metasploit)"
		author = "Elastic Security"
		id = "2092c42a-793b-4b0e-868b-9a39c926f44c"
		date = "2023-05-09"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Metasploit.yar#L290-L309"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e47d88c11a89dcc84257841de0c9f1ec388698006f55a0e15567354b33f07d3c"
		logic_hash = "83c46c6b957f10d406ea9985c518eb2fba3e82b9023bfdefa8bdd4be7fb67826"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "4f17bfb02d3ac97e48449b6e30c9b07f604c13d5e12a99af322853c5d656ee88"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 65 6E 61 62 6C 65 5F 6B 65 79 62 6F 61 72 64 5F 69 6E 70 75 74 }
		$a2 = { 01 04 10 49 83 C2 02 4D 85 C9 75 9C 41 8B 43 04 4C 03 D8 48 }

	condition:
		all of them
}