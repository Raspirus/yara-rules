rule ELASTIC_Windows_Trojan_Diamondfox_18Bc11E3 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Diamondfox (Windows.Trojan.DiamondFox)"
		author = "Elastic Security"
		id = "18bc11e3-5872-40b0-a3b7-cef4b32fac15"
		date = "2022-03-02"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_DiamondFox.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a44c46d4b9cf1254aaabd1e689f84c4d2c3dd213597f827acabface03a1ae6d1"
		logic_hash = "c64e4b3349b33cfd0fec1fe41f91ad819bb6b6751e822d7ab8d14638ad27571d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6f908d11220e218a7b59239ff3cc00c7e273fb46ec99ef7ae37e4aceb4de7831"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "\\wscript.vbs" wide fullword
		$a2 = "\\snapshot.jpg" wide fullword
		$a3 = "&soft=" wide fullword
		$a4 = "ping -n 4 127.0.0.1 > nul" wide fullword
		$a5 = "Select Name from Win32_Process Where Name = '" wide fullword

	condition:
		all of them
}