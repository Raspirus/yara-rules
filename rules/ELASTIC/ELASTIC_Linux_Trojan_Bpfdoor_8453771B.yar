
rule ELASTIC_Linux_Trojan_Bpfdoor_8453771B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Bpfdoor (Linux.Trojan.BPFDoor)"
		author = "Elastic Security"
		id = "8453771b-a78f-439d-be36-60439051586a"
		date = "2022-05-10"
		modified = "2022-05-10"
		reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_BPFDoor.yar#L52-L78"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
		logic_hash = "546e5c56ceb6b99db14dc225a2ec4872cb54859a0f2f6ad520d4f446793e031e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b9d07bda8909e7afb1a1411a3bad1e6cffec4a81eb47d42f2292a2c4c0d97fa7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "[-] Spawn shell failed." ascii fullword
		$a2 = "[+] Packet Successfuly Sending %d Size." ascii fullword
		$a3 = "[+] Monitor packet send." ascii fullword
		$a4 = "[+] Using port %d"
		$a5 = "decrypt_ctx" ascii fullword
		$a6 = "getshell" ascii fullword
		$a7 = "getpassw" ascii fullword
		$a8 = "export %s=%s" ascii fullword

	condition:
		all of them
}