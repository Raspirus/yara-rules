rule ELASTIC_Linux_Trojan_Metasploit_0C629849 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Metasploit (Linux.Trojan.Metasploit)"
		author = "Elastic Security"
		id = "0c629849-8127-4fec-a225-da29bf41435e"
		date = "2024-05-03"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Metasploit.yar#L26-L48"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ad070542729f3c80d6a981b351095ab8ac836b89a5c788dff367760a2d8b1dbb"
		logic_hash = "2bea8f569728ba81af4024bf062a06a5c91b1f057a0b62fe6d51b6fcadedf58c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3e98ffa46e438421056bf4424382baa6fbe30e5fc16dbd227bceb834873dbe41"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$socket_call = { 6A 29 58 6A 0A 5F 6A 01 5E 31 D2 0F 05 50 5F }
		$populate_sockaddr_in6 = { 99 52 52 52 66 68 }
		$calls = { 6A 31 58 6A 1C 5A 0F 05 6A 32 58 6A 01 5E 0F 05 6A 2B 58 99 52 52 54 5E 6A 1C 48 8D 14 24 0F 05 }
		$dup2 = { 48 97 6A 03 5E 6A 21 58 FF CE 0F 05 E0 F7 }
		$exec_call = { 6A 3B 58 99 48 BB 2F 62 69 6E 2F 73 68 00 53 54 5F 0F 05 }

	condition:
		all of them
}