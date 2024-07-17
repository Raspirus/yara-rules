rule ELASTIC_Macos_Trojan_Thiefquest_9130C0F3 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Thiefquest (MacOS.Trojan.Thiefquest)"
		author = "Elastic Security"
		id = "9130c0f3-5926-4153-87d8-85a591eed929"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Thiefquest.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bed3561210e44c290cd410adadcdc58462816a03c15d20b5be45d227cd7dca6b"
		logic_hash = "20e9ea15a437a17c4ef68f2472186f6d1ab3118d5b392f84fcb2bd376ec3863a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "38916235c68a329eea6d41dbfba466367ecc9aad2b8ae324da682a9970ec4930"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a1 = "heck_if_targeted" ascii fullword
		$a2 = "check_command" ascii fullword
		$a3 = "askroot" ascii fullword
		$a4 = "iv_rescue_data" ascii fullword

	condition:
		all of them
}