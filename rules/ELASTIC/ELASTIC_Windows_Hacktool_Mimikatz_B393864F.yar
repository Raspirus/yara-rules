
rule ELASTIC_Windows_Hacktool_Mimikatz_B393864F : FILE
{
	meta:
		description = "Subject: Open Source Developer, Benjamin Delpy"
		author = "Elastic Security"
		id = "b393864f-a9b0-47e7-aea4-0fc5a4a22a82"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_Mimikatz.yar#L135-L154"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8206ce9c42582ac980ff5d64f8e3e310bc2baa42d1a206dd831c6ab397fbd8fe"
		logic_hash = "d09cb7f753675e0b6ecd8a7977ca7f8d313e5d525f05170fc54b265c2ae6c188"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "bfd497290db97b7578d59e8d43a28ee736a3d7d23072eb67d28ada85cac08bd3"
		threat_name = "Windows.Hacktool.Mimikatz"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$subject_name = { 06 03 55 04 03 [2] 4F 70 65 6E 20 53 6F 75 72 63 65 20 44 65 76 65 6C 6F 70 65 72 2C 20 42 65 6E 6A 61 6D 69 6E 20 44 65 6C 70 79 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $subject_name
}