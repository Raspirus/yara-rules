rule ELASTIC_Linux_Trojan_Bpfdoor_F690Fe3B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Bpfdoor (Linux.Trojan.BPFDoor)"
		author = "Elastic Security"
		id = "f690fe3b-1b3f-4101-931b-10932596f546"
		date = "2022-05-10"
		modified = "2022-05-10"
		reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_BPFDoor.yar#L80-L99"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
		logic_hash = "35c6be75348a30f415a1a4bb94ae7e3a2f49f54a0fb3ddc4bae1aa3e03c1a909"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "504bfe57dcc3689881bdd0af55aab9a28dcd98e44b5a9255d2c60d9bc021130b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 45 D8 0F B6 10 0F B6 45 FF 48 03 45 F0 0F B6 00 8D 04 02 00 }

	condition:
		all of them
}