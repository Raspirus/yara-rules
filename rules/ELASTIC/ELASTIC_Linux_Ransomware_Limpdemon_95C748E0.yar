rule ELASTIC_Linux_Ransomware_Limpdemon_95C748E0 : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Limpdemon (Linux.Ransomware.LimpDemon)"
		author = "Elastic Security"
		id = "95c748e0-e2f5-4997-a69d-dbc8885e6f18"
		date = "2023-07-27"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_LimpDemon.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a4200e90a821a2f2eb3056872f06cf5b057be154dcc410274955b2aaca831651"
		logic_hash = "e66906725c0af657d91771642908ac0b2c72a97c4d4f651dcc907c2c1437f2da"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "20527c2e0d2e577c17da7184193ba372027cedb075f78bb75aff9d218c2d660b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "[-] You have to pass access key to start process" fullword
		$a2 = "[+] Shutting down VMWare ESXi servers..." fullword
		$a3 = "%s --daemon (start as a service)" fullword
		$a4 = "%s --access-key <key> (key for decryption config)" fullword

	condition:
		2 of them
}