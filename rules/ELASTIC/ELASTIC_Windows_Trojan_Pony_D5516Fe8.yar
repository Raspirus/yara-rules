rule ELASTIC_Windows_Trojan_Pony_D5516Fe8 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Pony (Windows.Trojan.Pony)"
		author = "Elastic Security"
		id = "d5516fe8-3b25-4c46-9e5b-111ca312a824"
		date = "2021-08-14"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Pony.yar#L1-L25"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "423e792fcd00265960877482e8148a0d49f0898f4bbc190894721fde22638567"
		logic_hash = "4a850d32fb28477e7e3fef2dda6ba327b800e2ebcae1a483970cde78f34a4ff7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9d4d847f55a693a45179a904efe20afd05a92650ac47fb19ef523d469a33795f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "\\Global Downloader" ascii fullword
		$a2 = "wiseftpsrvs.bin" ascii fullword
		$a3 = "SiteServer %d\\SFTP" ascii fullword
		$a4 = "%s\\Keychain" ascii fullword
		$a5 = "Connections.txt" ascii fullword
		$a6 = "ftpshell.fsi" ascii fullword
		$a7 = "inetcomm server passwords" ascii fullword

	condition:
		all of them
}