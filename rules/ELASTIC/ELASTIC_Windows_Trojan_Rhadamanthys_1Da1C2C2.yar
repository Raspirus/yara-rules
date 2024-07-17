rule ELASTIC_Windows_Trojan_Rhadamanthys_1Da1C2C2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Rhadamanthys (Windows.Trojan.Rhadamanthys)"
		author = "Elastic Security"
		id = "1da1c2c2-90ea-4f76-aa38-666934c0aa68"
		date = "2023-03-28"
		modified = "2023-04-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Rhadamanthys.yar#L27-L52"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9bfc4fed7afc79a167cac173bf3602f9d1f90595d4e41dab68ff54973f2cedc1"
		logic_hash = "bf5d45fe79dacfc6aee5cfd788ec6ce77e99e55d5a6d294da57c126bedf75ee9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7b3830373b773be03dc6d0f030595f625a2ef0b6a83312a5b0a958c0d2e5b1c0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "%s\\tdata\\key_datas" wide fullword
		$a2 = "\\config\\loginusers.vdf" wide fullword
		$a3 = "/bin/KeePassHax.dll" ascii fullword
		$a4 = "%%APPDATA%%\\ns%04x.dll" wide fullword
		$a5 = "\\\\.\\pipe\\{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}" wide fullword
		$a6 = " /s /n /i:\"%s,%u,%u,%u\" \"%s\"" wide fullword
		$a7 = "strbuf(%lx) reallocs: %d, length: %d, size: %d" ascii fullword
		$a8 = "SOFTWARE\\FTPWare\\CoreFTP\\Sites\\%s" wide fullword

	condition:
		6 of them
}