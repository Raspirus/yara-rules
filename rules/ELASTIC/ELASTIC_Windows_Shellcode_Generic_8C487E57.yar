
rule ELASTIC_Windows_Shellcode_Generic_8C487E57 : FILE MEMORY
{
	meta:
		description = "Detects Windows Shellcode Generic (Windows.Shellcode.Generic)"
		author = "Elastic Security"
		id = "8c487e57-4b8c-488e-a1d9-786ff935fd2c"
		date = "2022-05-23"
		modified = "2022-07-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Shellcode_Generic.yar#L1-L18"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "a86ea8e15248e83ce7322c10e308a5a24096b1d7c67f5673687563dec8229dfe"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "834caf96192a513aa93ac48fb8d2f3326bf9f08acaf7a27659f688b26e3e57e4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 }

	condition:
		all of them
}