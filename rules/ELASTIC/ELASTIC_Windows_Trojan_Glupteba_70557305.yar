rule ELASTIC_Windows_Trojan_Glupteba_70557305 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Glupteba (Windows.Trojan.Glupteba)"
		author = "Elastic Security"
		id = "70557305-3d11-4dde-b53b-94f1ecc0380b"
		date = "2021-08-08"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Glupteba.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3ad13fd7968f9574d2c822e579291c77a0c525991cfb785cbe6cdd500b737218"
		logic_hash = "f3eee9808a1e8a2080116dda7ce795815e1179143c756ea8fdd26070f1f8f74a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bac7daa5c491de8f8a75b203cdb1cdab2c10633aa45a82e6b04d2f577e3e8415"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "%TEMP%\\app.exe && %TEMP%\\app.exe"
		$a2 = "is unavailable%d smbtest"
		$a3 = "discovered new server %s"
		$a4 = "uldn't get usernamecouldn't hide servicecouldn't"
		$a5 = "TERMINATE PROCESS: %ws, %d, %d" ascii fullword
		$a6 = "[+] Extracting vulnerable driver as \"%ws\"" ascii fullword

	condition:
		all of them
}