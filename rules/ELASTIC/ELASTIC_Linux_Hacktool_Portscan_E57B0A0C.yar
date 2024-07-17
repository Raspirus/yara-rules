
rule ELASTIC_Linux_Hacktool_Portscan_E57B0A0C : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Portscan (Linux.Hacktool.Portscan)"
		author = "Elastic Security"
		id = "e57b0a0c-66b8-488b-b19d-ae06623645fd"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Portscan.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f8ee385316b60ee551565876287c06d76ac5765f005ca584d1ca6da13a6eb619"
		logic_hash = "b2f67805e9381864591fdf61846284da97f8dd2f5c60484ce9c6e76d2f6f3872"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "829c7d271ae475ef06d583148bbdf91af67ce4c7a831da73cc52e8406e7e8f9e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 10 83 7D 08 03 75 2B 83 EC 0C 8B 45 0C 83 C0 08 FF 30 8B 45 0C 83 }

	condition:
		all of them
}