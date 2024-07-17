
rule ELASTIC_Windows_Hacktool_Sharpdump_7C17D8B1 : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Sharpdump (Windows.Hacktool.SharpDump)"
		author = "Elastic Security"
		id = "7c17d8b1-35cf-440e-8f4e-44abdc2054bb"
		date = "2022-10-20"
		modified = "2022-11-24"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_SharpDump.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "14c3ea569a1bd9ac3aced4f8dd58314532dbf974bfa359979e6c7b6a4bbf41ca"
		logic_hash = "10ca29b097d9f1cef27349751e8f1e584ead1056a636224a80f00823ca878c13"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "cf1e23fc0a317959fceadae8984240b174dac22a1bcabccf43c34f0186a3ac23"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$guid = "9c9bba3-a0ea-431c-866c-77004802d" ascii wide nocase
		$print_str0 = "Please use \"SharpDump.exe [pid]\" format" ascii wide
		$print_str1 = "[*] Use \"sekurlsa::minidump debug.out\" \"sekurlsa::logonPasswords full\" on the same OS/arch" ascii wide
		$print_str2 = "[+] Dumping completed. Rename file to \"debug{0}.gz\" to decompress" ascii wide
		$print_str3 = "[X] Not in high integrity, unable to MiniDump!" ascii wide

	condition:
		$guid or all of ($print_str*)
}