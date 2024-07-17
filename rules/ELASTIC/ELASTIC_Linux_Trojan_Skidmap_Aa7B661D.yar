
rule ELASTIC_Linux_Trojan_Skidmap_Aa7B661D : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Skidmap (Linux.Trojan.Skidmap)"
		author = "Elastic Security"
		id = "aa7b661d-0ecc-4171-a0c2-a6c0c91b6d27"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Skidmap.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4282ba9b7bee69d42bfff129fff45494fb8f7db0e1897fc5aa1e4265cb6831d9"
		logic_hash = "aa976158d004d582234a92ff648d4581440f9c933a0abef212d9d837d9607ba4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0bd6bec14d4b0205b04c6b4f34988ad95161f954a1f0319dd33513cb2c7e5f59"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E8 41 41 80 F8 1A 41 0F 43 C1 88 04 0E 48 83 C1 01 0F B6 04 0F }

	condition:
		all of them
}