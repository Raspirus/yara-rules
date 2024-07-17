
rule ELASTIC_Windows_Trojan_Guloader_8F10Fa66 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Guloader (Windows.Trojan.Guloader)"
		author = "Elastic Security"
		id = "8f10fa66-a24b-4cc2-b9e0-11be14aba9af"
		date = "2021-08-17"
		modified = "2021-10-04"
		reference = "https://www.elastic.co/security-labs/getting-gooey-with-guloader-downloader"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Guloader.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a3e2d5013b80cd2346e37460753eca4a4fec3a7941586cc26e049a463277562e"
		logic_hash = "f2cd08f6a32c075dc0294a0e26c51e686babc54ced4faa1873368c8821f0bfef"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5841d70a38d4620c446427c80ca12b5e918f23e90c5288854943b0240958bcfb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "msvbvm60.dll" wide fullword
		$a2 = "C:\\Program Files\\qga\\qga.exe" ascii fullword
		$a3 = "C:\\Program Files\\Qemu-ga\\qemu-ga.exe" ascii fullword
		$a4 = "USERPROFILE=" wide fullword
		$a5 = "Startup key" ascii fullword

	condition:
		all of them
}