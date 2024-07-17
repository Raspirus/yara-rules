rule ELASTIC_Windows_Shellcode_Generic_29Dcbf7A : FILE MEMORY
{
	meta:
		description = "Detects Windows Shellcode Generic (Windows.Shellcode.Generic)"
		author = "Elastic Security"
		id = "29dcbf7a-2d3b-4e05-a2be-15623bf62d06"
		date = "2023-05-09"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Shellcode_Generic.yar#L39-L56"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "c2a81cc27e696a2e488df7d2f96784bbaed83df5783efab312fc5ccbfd524b43"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e4664ec7bf7dab3fff873fe4b059e97d2defe3b50e540b96dd98481638dcdcd8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { FC 48 83 E4 F0 41 57 41 56 41 55 41 54 55 53 56 57 48 83 EC 40 48 83 EC 40 48 83 EC 40 48 89 E3 }

	condition:
		all of them
}