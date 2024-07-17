rule ELASTIC_Windows_Wiper_Doublezero_65Ec0C50 : FILE MEMORY
{
	meta:
		description = "Detects Windows Wiper Doublezero (Windows.Wiper.DoubleZero)"
		author = "Elastic Security"
		id = "65ec0c50-4038-46a7-879b-fbb4aab18725"
		date = "2022-03-22"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Wiper_DoubleZero.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3b2e708eaa4744c76a633391cf2c983f4a098b46436525619e5ea44e105355fe"
		logic_hash = "bce33817d99f71b9d087ea079ef8db08b496315b72cf9d1cf6f0b107a604e52c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2441bcdf7bc48df098f4ef68231fb15fc5c8f96af2e170de77f1718487b945b2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$s1 = "\\Users\\\\.*?\\\\AppData\\\\Roaming\\\\Microsoft.*" wide fullword
		$s2 = "\\Users\\\\.*?\\\\AppData\\\\Local\\\\Application Data.*" wide fullword
		$s3 = "\\Users\\\\.*?\\\\Local Settings.*" wide fullword
		$s4 = "get__beba00adeeb086e6" ascii fullword
		$s5 = "FileShareWrite" ascii fullword

	condition:
		all of them
}