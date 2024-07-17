rule ELASTIC_Windows_Hacktool_Safetykatz_072B7370 : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Safetykatz (Windows.Hacktool.SafetyKatz)"
		author = "Elastic Security"
		id = "072b7370-517b-45dc-af23-ba3adbd32fbd"
		date = "2022-11-20"
		modified = "2023-01-11"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_SafetyKatz.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "89a456943cf6d2b3cd9cdc44f13a23640575435ed49fa754f7ed358c1a3b6ba9"
		logic_hash = "cedd3ede487371a8e0d29804f2b81ae808c7ad01bd803fa39dc2c50e472cff43"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "f0d11341fc91d2c45c07c6079aad24a11da03320286216be0a68461b6bf55b02"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$guid = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" ascii wide nocase
		$print_str0 = "[X] Not in high integrity, unable to grab a handle to lsass!" ascii wide fullword
		$print_str1 = "[X] Dump directory \"{0}\" doesn't exist!" ascii wide fullword
		$print_str2 = "[X] Process is not 64-bit, this version of Mimikatz won't work yo'!" ascii wide fullword
		$print_str3 = "[+] Dump successful!" ascii wide fullword

	condition:
		$guid or all of ($print_str*)
}