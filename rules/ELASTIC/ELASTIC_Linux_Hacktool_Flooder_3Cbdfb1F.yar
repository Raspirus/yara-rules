rule ELASTIC_Linux_Hacktool_Flooder_3Cbdfb1F : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "3cbdfb1f-6c66-48be-931e-3ae609c46ff4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L220-L238"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bd40ac964f3ad2011841c7eb4bf7cab332d4d95191122e830ab031dc9511c079"
		logic_hash = "38e8ca59bf55c32b99aa76a89f60edcf09956b7cad0b4745fab92eca327c52db"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "c7f5d7641ea6e780bc3045181c929be73621acfe6aec4d157f6a9e0334ba7fb9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 5B 53 54 44 32 2E 43 20 42 59 20 53 54 41 43 4B 44 5D 20 53 }

	condition:
		all of them
}