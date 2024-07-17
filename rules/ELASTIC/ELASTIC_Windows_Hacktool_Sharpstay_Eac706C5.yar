
rule ELASTIC_Windows_Hacktool_Sharpstay_Eac706C5 : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Sharpstay (Windows.Hacktool.SharpStay)"
		author = "Elastic Security"
		id = "eac706c5-975e-43f2-b106-149f884a2e9a"
		date = "2022-11-20"
		modified = "2023-01-11"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_SharpStay.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "498d201f65b57a007a79259ce7015eb7eb1bba660d44deafea716e36316a9caa"
		logic_hash = "b85679018658e33e81cd2589e9f99cf9ed16ac25b27d93bece26cb5ccc2e379a"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "346e6cf9d85c737b171914b331bb1837f90696301dbe144cbf8996b8a8cb3adb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$guid = "2963C954-7B1E-47F5-B4FA-2FC1F0D56AEA" ascii wide nocase
		$print_str0 = "[+] Registry key HKCU:SOFTWARE\\Classes\\CLSID\\{0}\\InProcServer32 created" ascii wide fullword
		$print_str1 = "Sharpstay.exe action=ElevatedRegistryKey" ascii wide fullword
		$print_str2 = "[+] WMI Subscription {0} has been created to run at {1}" ascii wide fullword
		$print_str3 = "[+] Cleaned up %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Accessories\\Indexing.{0}" ascii wide fullword

	condition:
		$guid or all of ($print_str*)
}