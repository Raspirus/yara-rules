rule ELASTIC_Windows_Hacktool_Clroxide_D92D9575 : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Clroxide (Windows.Hacktool.ClrOxide)"
		author = "Elastic Security"
		id = "d92d9575-9ad9-464f-95a3-8e100666d7fa"
		date = "2024-02-29"
		modified = "2024-03-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_ClrOxide.yar#L1-L25"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f3a4900eff80563bff586ced172c3988347980f902aceef2f9f9f6d188fac8e3"
		logic_hash = "01bb071e1286bb139c5e1c37e421153ef1b28a5994feeaedf6ad27ad7dade5e9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b403acddadc5adb982a9ee0e0513ecd471b728680cc9a6cd8cd8150eb9c02776"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$s1 = "clroxide..primitives..imethodinfo"
		$s2 = "clroxide..clr..Clr"
		$s3 = "\\src\\primitives\\icorruntimehost.rs"
		$s4 = "\\src\\primitives\\iclrruntimeinfo.rs"
		$s5 = "\\src\\primitives\\iclrmetahost.rs"
		$s6 = "clroxide\\src\\clr\\mod.rs"
		$s7 = "__clrcall"

	condition:
		2 of them
}