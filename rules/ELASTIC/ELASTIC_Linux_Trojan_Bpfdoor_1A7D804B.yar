
rule ELASTIC_Linux_Trojan_Bpfdoor_1A7D804B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Bpfdoor (Linux.Trojan.BPFDoor)"
		author = "Elastic Security"
		id = "1a7d804b-9d39-4855-abe9-47b72bd28f07"
		date = "2022-05-10"
		modified = "2022-05-10"
		reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_BPFDoor.yar#L101-L127"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
		logic_hash = "b0c4b168d92947e599e8c74d0ae6a91766c8a034c34e9c07e2472620c9b61037"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e7f92df3e3929b8296320300bb341ccc69e00d89e0d503a41190d7c84a29bce2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "getshell" ascii fullword
		$a2 = "/sbin/agetty --noclear tty1 linux" ascii fullword
		$a3 = "packet_loop" ascii fullword
		$a4 = "godpid" ascii fullword
		$a5 = "ttcompat" ascii fullword
		$a6 = "decrypt_ctx" ascii fullword
		$a7 = "rc4_init" ascii fullword
		$b1 = { D0 48 89 45 F8 48 8B 45 F8 0F B6 40 0C C0 E8 04 0F B6 C0 C1 }

	condition:
		all of ($a*) or 1 of ($b*)
}