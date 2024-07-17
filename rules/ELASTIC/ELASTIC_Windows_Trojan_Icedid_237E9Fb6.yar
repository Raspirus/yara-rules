
rule ELASTIC_Windows_Trojan_Icedid_237E9Fb6 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Icedid (Windows.Trojan.IcedID)"
		author = "Elastic Security"
		id = "237e9fb6-b5fa-4747-af1f-533c76a5a639"
		date = "2021-02-28"
		modified = "2021-08-23"
		reference = "https://www.fireeye.com/blog/threat-research/2021/02/melting-unc2198-icedid-to-ransomware-operations.html"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_IcedID.yar#L23-L43"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b21f9afc6443548427bf83b5f93e7a54ac3af306d9d71b8348a6f146b2819457"
		logic_hash = "31479eae077b2d78cb1770eef3b37bec941f35c9ceb329e01dd65a32e785fa74"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e2ea6d1477ce4132f123b6c00101a063f7bba7acf38be97ee8dca22cc90ed511"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 60 8B 55 D4 3B D0 7E 45 83 F8 08 0F 4C 45 EC 3B D0 8D 3C 00 0F }

	condition:
		all of them
}