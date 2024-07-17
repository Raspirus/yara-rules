rule ELASTIC_Windows_Trojan_Bumblebee_70Bed4F3 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bumblebee (Windows.Trojan.Bumblebee)"
		author = "Elastic Security"
		id = "70bed4f3-f515-4186-ac6c-e9db72b8a95a"
		date = "2022-04-28"
		modified = "2022-06-09"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Bumblebee.yar#L22-L46"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9fff05a5aa9cbbf7d37bc302d8411cbd63fb3a28dc6f5163798ae899b9edcda6"
		logic_hash = "3ff97986bfd8df812c4ef94395b3ac7f9ead4d059c398f8984ee217a1bcee4af"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "016477598ce022cc75f591d1c72535a3353ecc4e888642e72aa29476464a8c2f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Checking Virtual PC processes %s " wide fullword
		$a2 = "SELECT * FROM Win32_ComputerSystemProduct" ascii fullword
		$a3 = "Injection-Date" ascii fullword
		$a4 = " -Command \"Wait-Process -Id " ascii fullword
		$a5 = "%WINDIR%\\System32\\wscript.exe" wide fullword
		$a6 = "objShell.Run \"rundll32.exe my_application_path"
		$a7 = "Checking reg key HARDWARE\\Description\\System - %s is set to %s" wide fullword

	condition:
		5 of them
}