
rule ELASTIC_Windows_Hacktool_Sharprdp_80895Fcb : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Sharprdp (Windows.Hacktool.SharpRDP)"
		author = "Elastic Security"
		id = "80895fcb-b98e-4865-a1f6-87cbea327cea"
		date = "2022-11-20"
		modified = "2023-01-11"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_SharpRDP.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6e909861781a8812ee01bc59435fd73fd34da23fa9ad6d699eefbf9f84629876"
		logic_hash = "ef9a92f2ed29f508dca591e9c65a6ce0013ccdfd0c62770e8840be2f3ee5982e"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "a7eb084004fce79efc39781044bad501a731163fa3ad6f9b8b334611d03f5379"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$guid = "F1DF1D0F-FF86-4106-97A8-F95AAF525C54" ascii wide nocase
		$print_str0 = "[+] Another user is logged on, asking to take over session" ascii wide fullword
		$print_str1 = "[+] Execution priv type   :  {0}" ascii wide fullword
		$print_str2 = "[+] Sleeping for 30 seconds" ascii wide fullword
		$print_str3 = "[X] Error: A password is required" ascii wide fullword

	condition:
		$guid or all of ($print_str*)
}