rule ELASTIC_Windows_Trojan_Metasploit_B62Aac1E : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Metasploit (Windows.Trojan.Metasploit)"
		author = "Elastic Security"
		id = "b62aac1e-2ce8-4803-90ee-138b509e814d"
		date = "2023-05-10"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Metasploit.yar#L332-L351"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "af9af81f7e46217330b447900f80c9ce38171655becb3b63e51f913b95c71e70"
		logic_hash = "3ef6b7fb258b060ae00b060dbf9b07620f8cda0d9a827985bbb3ed9617969ef6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "58340ea67e2544d22adba3317350150c61c84fba1d16c7c9f8d0c626c3421296"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 42 3C 8B AC 10 88 00 00 00 44 8B 54 15 20 44 8B 5C 15 24 4C }
		$a2 = { CB 4D 85 D2 74 10 41 8A 00 4D 03 C3 88 02 49 03 D3 4D 2B D3 }

	condition:
		all of them
}