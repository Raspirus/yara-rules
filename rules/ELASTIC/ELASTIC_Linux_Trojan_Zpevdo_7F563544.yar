
rule ELASTIC_Linux_Trojan_Zpevdo_7F563544 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Zpevdo (Linux.Trojan.Zpevdo)"
		author = "Elastic Security"
		id = "7f563544-4ef3-460f-9a36-23d086f9c421"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Zpevdo.yar#L1-L18"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "9cbbb5a9166184cef630d1aba8fec721f676b868d22b1f96ffc1430e98ae974c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a2113b38c27ee7e22313bd0ffbcabadfbf7f3f33d241a97db2dc86299775afd6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 55 48 89 E5 48 83 EC 20 89 7D EC 48 89 75 E0 BE 01 00 00 00 BF 11 00 }

	condition:
		all of them
}