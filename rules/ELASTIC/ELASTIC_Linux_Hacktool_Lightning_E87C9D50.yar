
rule ELASTIC_Linux_Hacktool_Lightning_E87C9D50 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Lightning (Linux.Hacktool.Lightning)"
		author = "Elastic Security"
		id = "e87c9d50-dafc-45bd-8786-5df646108c8a"
		date = "2022-11-08"
		modified = "2024-02-13"
		reference = "https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Lightning.yar#L25-L48"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fd285c2fb4d42dde23590118dba016bf5b846625da3abdbe48773530a07bcd1e"
		logic_hash = "455ecf97e7becaf9c40843f8a3f60ec233d35e0061c6994f168428a8835c1b20"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "22b982866241d50b6e5d964ee190f6d07982a5d3f0b2352d863c20432d5f785e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "Execute %s Faild." ascii fullword
		$a2 = "Lightning.Downloader" ascii fullword
		$a3 = "Execute %s Success." ascii fullword
		$a4 = "[-] Socks5 are Running!" ascii fullword
		$a5 = "[-] Get FileInfo(%s) Faild!" ascii fullword

	condition:
		all of them
}