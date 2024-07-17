
rule ELASTIC_Windows_Trojan_Afdk_5F8Cc135 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Afdk (Windows.Trojan.Afdk)"
		author = "Elastic Security"
		id = "5f8cc135-88b1-478d-aedb-0d60cee0bbf2"
		date = "2023-12-01"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Afdk.yar#L21-L41"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6723a9489e7cfb5e2d37ff9160d55cda065f06907122d73764849808018eb7a0"
		logic_hash = "0523a0cc3a4446f2ac88c72999568313c6b40f7f8975b8e332c0c6b1e48c5d76"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "275bfaac332f3cbc1164c35bdbc5cbe8bfd45559f6b929a0b8b64af2de241bd8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Cannot set the log file name"
		$a2 = "Cannot install the hook procedure"
		$a3 = "Keylogger is up and running..."

	condition:
		2 of them
}