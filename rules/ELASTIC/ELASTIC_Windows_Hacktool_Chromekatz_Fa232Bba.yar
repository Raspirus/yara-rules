
rule ELASTIC_Windows_Hacktool_Chromekatz_Fa232Bba : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Chromekatz (Windows.Hacktool.ChromeKatz)"
		author = "Elastic Security"
		id = "fa232bba-07dd-45e0-9ca3-b1465eb9616d"
		date = "2024-03-27"
		modified = "2024-05-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_ChromeKatz.yar#L1-L28"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3f6922049422df14f1a1777001fea54b18fbfb0a4b03c4ee27786bfbc3b8ab87"
		logic_hash = "c86291fadd51845cbd7428b159e401d78ac77090e14e34d06bf7bf2018f4502a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bf1da659e0de9c4e22851e77878066ae5f4aca75e61b35392887c12e125c91f8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$s1 = "CookieKatz.exe"
		$s2 = "Targeting Chrome"
		$s3 = "Targeting Msedgewebview2"
		$s4 = "Failed to find the first pattern"
		$s5 = "WalkCookieMap"
		$s6 = "Found CookieMonster on 0x%p"
		$s7 = "Cookie Key:"
		$s8 = "Failed to read cookie value" wide
		$s9 = "Failed to read cookie struct" wide
		$s10 = "Error reading left node"

	condition:
		5 of them
}