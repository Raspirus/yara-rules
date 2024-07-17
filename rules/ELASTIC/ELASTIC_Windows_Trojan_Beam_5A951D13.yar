rule ELASTIC_Windows_Trojan_Beam_5A951D13 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Beam (Windows.Trojan.Beam)"
		author = "Elastic Security"
		id = "5a951d13-9568-4a5f-bda3-645143bc16a1"
		date = "2021-12-07"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Beam.yar#L24-L42"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "233a1f1dcbb679d31dab7744358b434cccabfc752baf53ba991388ced098f7c8"
		logic_hash = "3419b649717b69f07334bd966f438dd0b77f03572fe14f4b88ce95a2a86cae07"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e3de6b47e563ebfd735cdd56f5b4077a8923026520ecca0628c5704272ea52bb"
		severity = 99
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 24 40 8B CE 2B C8 3B CA 0F 42 D1 83 FF 10 8D 4C 24 18 0F 43 CB }

	condition:
		all of them
}