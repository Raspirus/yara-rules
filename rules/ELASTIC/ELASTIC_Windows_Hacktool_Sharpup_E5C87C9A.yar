rule ELASTIC_Windows_Hacktool_Sharpup_E5C87C9A : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Sharpup (Windows.Hacktool.SharpUp)"
		author = "Elastic Security"
		id = "e5c87c9a-6b4d-49af-85d1-6bb60123c057"
		date = "2022-10-20"
		modified = "2022-11-24"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_SharpUp.yar#L1-L25"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "45e92b991b3633b446473115f97366d9f35acd446d00cd4a05981a056660ad27"
		logic_hash = "62e9aafd308aacbc7a124c707e230c5a9ffde4f6929a5feada5497e3eae7668c"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "4c6e70b7ce3eb3fc05966af6c3847f4b7282059e05c089c20f39f226efb9bf87"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$guid = "FDD654F5-5C54-4D93-BF8E-FAF11B00E3E9" ascii wide nocase
		$str0 = "^\\W*([a-z]:\\\\.+?(\\.exe|\\.bat|\\.ps1|\\.vbs))\\W*" ascii wide
		$str1 = "^\\W*([a-z]:\\\\.+?(\\.exe|\\.dll|\\.sys))\\W*" ascii wide
		$str2 = "SELECT * FROM win32_service WHERE Name LIKE '{0}'" ascii wide
		$print_str1 = "[!] Modifialbe scheduled tasks were not evaluated due to permissions." ascii wide
		$print_str2 = "[+] Potenatially Hijackable DLL: {0}" ascii wide
		$print_str3 = "Registry AutoLogon Found" ascii wide

	condition:
		$guid or ( all of ($str*) and 1 of ($print_str*))
}