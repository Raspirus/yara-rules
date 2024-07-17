rule ELASTIC_Windows_Ransomware_Pandora_Bca8Ce23 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Pandora (Windows.Ransomware.Pandora)"
		author = "Elastic Security"
		id = "bca8ce23-6722-4cda-b5fa-623eda4fca1b"
		date = "2022-03-14"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Pandora.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2c940a35025dd3847f7c954a282f65e9c2312d2ada28686f9d1dc73d1c500224"
		logic_hash = "52203c1af994667ba6833defe547e886dd02167e4d76c57711080e3be0473bfc"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0da732f6bdf24f35dee3c1bf85435650a5ce9b5c6a93f01176659943c01ad711"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "/c vssadmin.exe delete shadows /all /quiet" wide fullword
		$a2 = "\\Restore_My_Files.txt" wide fullword
		$a3 = ".pandora" wide fullword

	condition:
		all of them
}