rule ELASTIC_Linux_Ransomware_Lockbit_D248E80E : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Lockbit (Linux.Ransomware.Lockbit)"
		author = "Elastic Security"
		id = "d248e80e-3e2f-4957-adc3-0c912b0cd386"
		date = "2023-07-27"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_Lockbit.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4800a67ceff340d2ab4f79406a01f58e5a97d589b29b35394b2a82a299b19745"
		logic_hash = "5d33d243cd7f9d9189139eb34a4dd8d81882be200223d5c8e60dfd07ca98f94b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "417ecf5a0b6030ed5b973186efa1e72dfa56886ba6cfc5fbf615e0814c24992f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "restore-my-files.txt" fullword
		$b1 = "xkeyboard-config" fullword
		$b2 = "bootsect.bak" fullword
		$b3 = "lockbit" fullword
		$b4 = "Error: %s" fullword
		$b5 = "crypto_generichash_blake2b_final" fullword

	condition:
		$a1 and 2 of ($b*)
}