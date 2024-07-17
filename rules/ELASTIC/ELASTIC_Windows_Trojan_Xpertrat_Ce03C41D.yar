rule ELASTIC_Windows_Trojan_Xpertrat_Ce03C41D : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Xpertrat (Windows.Trojan.Xpertrat)"
		author = "Elastic Security"
		id = "ce03c41d-d5c3-43f5-b3ca-f244f177d710"
		date = "2021-08-06"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Xpertrat.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d7f2fddb43eb63f9246f0a4535dfcca6da2817592455d7eceaacde666cf1aaae"
		logic_hash = "f6ff0a11f261bc75c9d0015131f177d39bb9e8e30346a75209ba8fa808ac4fcb"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8aa4336ba6909c820f1164c78453629959e28cb619fda45dbe46291f9fbcbec4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "[XpertRAT-Mutex]" wide fullword
		$a2 = "XPERTPLUGIN" wide fullword
		$a3 = "keylog.tmp" wide fullword

	condition:
		all of them
}