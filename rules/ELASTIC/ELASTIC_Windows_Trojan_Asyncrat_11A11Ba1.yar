rule ELASTIC_Windows_Trojan_Asyncrat_11A11Ba1 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Asyncrat (Windows.Trojan.Asyncrat)"
		author = "Elastic Security"
		id = "11a11ba1-c178-4415-9c09-45030b500f50"
		date = "2021-08-05"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Asyncrat.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fe09cd1d13b87c5e970d3cbc1ebc02b1523c0a939f961fc02c1395707af1c6d1"
		logic_hash = "c6c4ce9ccf01c280be6c25c0c82c34b601626bc200b84d3e77b08be473335d3d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "715ede969076cd413cebdfcf0cdda44e3a6feb5343558f18e656f740883b41b8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" wide fullword
		$a2 = "Stub.exe" wide fullword
		$a3 = "get_ActivatePong" ascii fullword
		$a4 = "vmware" wide fullword
		$a5 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide fullword
		$a6 = "get_SslClient" ascii fullword

	condition:
		all of them
}