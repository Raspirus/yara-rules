rule ELASTIC_Windows_Trojan_Generic_F0C79978 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Generic (Windows.Trojan.Generic)"
		author = "Elastic Security"
		id = "f0c79978-2df9-4ae2-bc5d-b5366acff41b"
		date = "2023-07-27"
		modified = "2023-09-20"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Generic.yar#L219-L238"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8f800b35bfbc8474f64b76199b846fe56b24a3ffd8c7529b92ff98a450d3bd38"
		logic_hash = "b16971ed0947660dda8d79c11531a9498a80e00f2dbc2c0eb63895b7f5c5f980"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "94b2a5784ae843b831f9ce34e986b2687ded5c754edf44ff20490b851e0261fc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "\\IronPython."
		$a2 = "\\helpers\\execassembly_x64"

	condition:
		all of them
}