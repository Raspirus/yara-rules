
rule ELASTIC_Linux_Hacktool_Flooder_A598192A : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "a598192a-c804-4c57-9cc3-c2205cb431d3"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "101f2240cd032831b9c0930a68ea6f74688f68ae801c776c71b488e17bc71871"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L540-L558"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "19909f53acca8c84125c95fc651765a25162c5f916366da8351e67675393e583"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "61cb72180283746ebbd82047baffc4bf2384658019970c4dceadfb5c946abcd2"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 8D 65 D8 5B 5E 5F C9 C3 8D 36 55 89 E5 83 EC 18 57 56 53 8B }

	condition:
		all of them
}