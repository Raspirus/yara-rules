rule ELASTIC_Linux_Trojan_Bpfdoor_E14B0B79 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Bpfdoor (Linux.Trojan.BPFDoor)"
		author = "Elastic Security"
		id = "e14b0b79-a6f3-4fb3-a314-0ec20dcd242c"
		date = "2022-05-10"
		modified = "2022-05-10"
		reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_BPFDoor.yar#L129-L152"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "dc8346bf443b7b453f062740d8ae8d8d7ce879672810f4296158f90359dcae3a"
		logic_hash = "7cdf111ae253bffef7243ad3722f1a79f81f45d80f938f9542af8e056f75d3fc"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1c4cb6c8a255840c5a2cb7674283678686e228dc2f2a9304fa118bb5bdc73968"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "getpassw" ascii fullword
		$a2 = "(udp[8:2]=0x7255) or (icmp[8:2]=0x7255) or (tcp[((tcp[12]&0xf0)>>2):2]=0x5293)" ascii fullword
		$a3 = "/var/run/haldrund.pid" ascii fullword
		$a4 = "Couldn't install filter %s: %s" ascii fullword
		$a5 = "godpid" ascii fullword

	condition:
		all of them
}