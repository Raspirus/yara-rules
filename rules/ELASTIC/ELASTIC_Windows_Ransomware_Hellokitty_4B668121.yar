
rule ELASTIC_Windows_Ransomware_Hellokitty_4B668121 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Hellokitty (Windows.Ransomware.Hellokitty)"
		author = "Elastic Security"
		id = "4b668121-cc21-4f0b-b0fc-c2b5b4cb53e8"
		date = "2021-05-03"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Hellokitty.yar#L34-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9a7daafc56300bd94ceef23eac56a0735b63ec6b9a7a409fb5a9b63efe1aa0b0"
		logic_hash = "00c7a492c304f12b9909e35cf069618a1103311a69e3e8951ca196c3c663b12a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "834316ce0f3225b1654b3c4bccb673c9ad815e422276f61e929d5440ca51a9fa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "(%d) [%d] %s: STOP DOUBLE PROCESS RUN" ascii fullword
		$a2 = "(%d) [%d] %s: Looking for folder from cmd: %S" ascii fullword
		$a3 = "(%d) [%d] %s: ERROR: Failed to encrypt AES block" ascii fullword
		$a4 = "gHelloKittyMutex" wide fullword
		$a5 = "/C ping 127.0.0.1 & del %s" wide fullword
		$a6 = "Trying to decrypt or modify the files with programs other than our decryptor can lead to permanent loss of data!"
		$a7 = "read_me_lkdtt.txt" wide fullword
		$a8 = "If you want to get it, you must pay us some money and we will help you." wide fullword

	condition:
		5 of them
}