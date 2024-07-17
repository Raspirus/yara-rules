
rule ELASTIC_Linux_Trojan_Mirai_D2205527 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "d2205527-0545-462b-b3c9-3bf2bdc44c6c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L930-L948"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e4f584d1f75f0d7c98b325adc55025304d55907e8eb77b328c007600180d6f06"
		logic_hash = "172ba256873cce61047a5198733cacaff4ef343c9cbd76f2fbbf0e1ed8003236"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "01d937fe8823e5f4764dea9dfe2d8d789187dcd6592413ea48e13f41943d67fd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { CA B8 37 00 00 00 0F 05 48 3D 01 F0 FF FF 73 01 C3 48 C7 C1 C0 FF }

	condition:
		all of them
}