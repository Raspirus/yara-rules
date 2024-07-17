rule ELASTIC_Windows_Rootkit_R77_Ee853C9F : FILE MEMORY
{
	meta:
		description = "Detects Windows Rootkit R77 (Windows.Rootkit.R77)"
		author = "Elastic Security"
		id = "ee853c9f-97ec-45b2-8c67-7b86331f4946"
		date = "2023-05-18"
		modified = "2023-06-13"
		reference = "https://www.elastic.co/security-labs/elastic-security-labs-steps-through-the-r77-rootkit"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Rootkit_R77.yar#L87-L112"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "916c805b0d512dd7bbd88f46632d66d9613de61691b4bd368e4b7cb1f0ac7f60"
		logic_hash = "94f080f310ecace76da32ba2b4edcc80dedfb339113823708167c1d842db8cf3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a2bf137ff29044a1f80494aa4b51bd7aa49ae64808b9f1d4566750b9717b847d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$r77_str0 = "$77stager" wide fullword
		$r77_str1 = "$77svc32" wide fullword
		$r77_str2 = "$77svc64" wide fullword
		$r77_str3 = "\\\\.\\pipe\\$77childproc64" wide fullword
		$r77_str4 = "SOFTWARE\\$77config"
		$obfuscate_ps = { 0F B7 04 4B 33 D2 C7 45 FC 34 00 00 00 F7 75 FC 66 8B 44 55 90 66 89 04 4B 41 3B CE }
		$amsi_patch_ps = "[Runtime.InteropServices.Marshal]::Copy([Byte[]](0xb8,0x57,0,7,0x80,0xc3)" wide fullword

	condition:
		($obfuscate_ps and $amsi_patch_ps) or ( all of ($r77_str*))
}