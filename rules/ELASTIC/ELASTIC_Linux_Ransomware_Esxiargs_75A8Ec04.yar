
rule ELASTIC_Linux_Ransomware_Esxiargs_75A8Ec04 : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Esxiargs (Linux.Ransomware.Esxiargs)"
		author = "Elastic Security"
		id = "75a8ec04-c41d-4702-94fa-976870762aaf"
		date = "2023-02-09"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_Esxiargs.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "11b1b2375d9d840912cfd1f0d0d04d93ed0cddb0ae4ddb550a5b62cd044d6b66"
		logic_hash = "7316cab75c1bcf41ae6c96afa41ef96c37ab1bb679f36a0cc1dd08002a357165"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "279259c7ca41331b09842c2221139d249d6dfe2e2cb6b27eb50af7be75120ce4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$s1 = "number of MB in encryption block"
		$s2 = "number of MB to skip while encryption"
		$s3 = "get_pk_data: key file is empty"
		$s4 = { 6F 70 65 6E 00 6C 73 65 65 6B 20 5B 65 6E 64 5D 00 6F 70 65 6E 5F 70 6B 5F 66 69 6C 65 }
		$s5 = "[<enc_step>] [<enc_size>] [<file_size>]"

	condition:
		3 of them
}