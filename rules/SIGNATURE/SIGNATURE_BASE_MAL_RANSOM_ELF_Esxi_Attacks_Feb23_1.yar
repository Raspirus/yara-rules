rule SIGNATURE_BASE_MAL_RANSOM_ELF_Esxi_Attacks_Feb23_1 : FILE
{
	meta:
		description = "Detects ransomware exploiting and encrypting ESXi servers"
		author = "Florian Roth"
		id = "d0a813aa-41f8-57df-b708-18ccb0d7a3e5"
		date = "2023-02-04"
		modified = "2023-12-05"
		reference = "https://www.bleepingcomputer.com/forums/t/782193/esxi-ransomware-help-and-support-topic-esxiargs-args-extension/page-14"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_ransom_esxi_attacks_feb23.yar#L30-L56"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "27ff018574323c10821993c30cf74de15121caa92a308fbcae4eceae954e63b6"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "11b1b2375d9d840912cfd1f0d0d04d93ed0cddb0ae4ddb550a5b62cd044d6b66"

	strings:
		$x1 = "usage: encrypt <public_key> <file_to_encrypt> [<enc_step>] [<enc_size>] [<file_size>]" ascii fullword
		$x2 = "[ %s ] - FAIL { Errno: %d }" ascii fullword
		$s1 = "lPEM_read_bio_RSAPrivateKey" ascii fullword
		$s2 = "lERR_get_error" ascii fullword
		$s3 = "get_pk_data: key file is empty!" ascii fullword
		$op1 = { 8b 45 a8 03 45 d0 89 45 d4 8b 45 a4 69 c0 07 53 65 54 89 45 a8 8b 45 a8 c1 c8 19 }
		$op2 = { 48 89 95 40 fd ff ff 48 83 bd 40 fd ff ff 00 0f 85 2e 01 00 00 48 8b 9d 50 ff ff ff 48 89 9d 30 fd ff ff 48 83 bd 30 fd ff ff 00 78 13 f2 48 0f 2a 85 30 fd ff ff }
		$op3 = { 31 55 b4 f7 55 b8 8b 4d ac 09 4d b8 8b 45 b8 31 45 bc c1 4d bc 13 c1 4d b4 1d }

	condition:
		uint16(0)==0x457f and filesize <200KB and (1 of ($x*) or 3 of them ) or 4 of them
}