rule ELASTIC_Windows_Ransomware_Whispergate_3476008E : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Whispergate (Windows.Ransomware.WhisperGate)"
		author = "Elastic Security"
		id = "3476008e-1c98-4606-b60b-7fef0e360711"
		date = "2022-01-18"
		modified = "2022-01-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_WhisperGate.yar#L22-L43"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9ef7dbd3da51332a78eff19146d21c82957821e464e8133e9594a07d716d892d"
		logic_hash = "729818df1b6b82fc00eba0fe1c9139ec4746e1775146ab7fdea9e25dec1cddea"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0b8caff8cf9342bd50053712bf4c9aeab68532e340cc5e6cf400105afc150e39"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "cmd.exe /min /C ping 111.111.111.111 -n 5 -w 10 > Nul & Del /f /q \"%s\"" ascii fullword
		$a2 = "%.*s.%x" wide fullword
		$a3 = "A:\\Windows" wide fullword
		$a4 = ".ONETOC2" wide fullword

	condition:
		all of them
}