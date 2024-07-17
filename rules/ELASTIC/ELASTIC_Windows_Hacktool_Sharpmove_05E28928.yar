
rule ELASTIC_Windows_Hacktool_Sharpmove_05E28928 : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Sharpmove (Windows.Hacktool.SharpMove)"
		author = "Elastic Security"
		id = "05e28928-6109-4afe-bd86-908d354ddd80"
		date = "2022-11-20"
		modified = "2023-01-11"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_SharpMove.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "051f60f9f4665b96f764810defe9525ae7b4f9898249b83a23094cee63fa0c3b"
		logic_hash = "021a56dd47d9929e71b82b00d24aa8969a31945681dcf414c69b8d175fb0b6eb"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "634efb2dedbb181a31ea41ff34d1d0810d1ab4823c8611737d68cb56601a052d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$guid = "8BF82BBE-909C-4777-A2FC-EA7C070FF43E" ascii wide nocase
		$print_str0 = "[X]  Failed to connecto to WMI: {0}" ascii wide fullword
		$print_str1 = "[+] Executing DCOM ShellBrowserWindow   : {0}" ascii wide fullword
		$print_str2 = "[+]  User credentials  : {0}" ascii wide fullword
		$print_str3 = "[+] Executing DCOM ExcelDDE   : {0}" ascii wide fullword

	condition:
		$guid or all of ($print_str*)
}