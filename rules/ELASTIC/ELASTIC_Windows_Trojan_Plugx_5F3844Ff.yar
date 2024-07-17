rule ELASTIC_Windows_Trojan_Plugx_5F3844Ff : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Plugx (Windows.Trojan.PlugX)"
		author = "Elastic Security"
		id = "5f3844ff-2da6-48b4-9afb-343149af03ac"
		date = "2023-08-28"
		modified = "2023-09-20"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_PlugX.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a823380e46878dfa8deb3ca0dc394db1db23bb2544e2d6e49c0eceeffb595875"
		logic_hash = "a1a484f4cf00ec0775a3f322bae66ce5f9cc52f08306b38f079445233c49bf52"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5365e6978ffca67e232165bca7bcdc5064abd5c589e49e19aa640f59dd5285ab"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "EAddr:0x%p"
		$a2 = "Host: [%s:%d]" ascii fullword
		$a3 = "CONNECT %s:%d HTTP/1.1" ascii fullword
		$a4 = "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d:" wide fullword
		$a5 = "\\bug.log" wide fullword

	condition:
		all of them
}