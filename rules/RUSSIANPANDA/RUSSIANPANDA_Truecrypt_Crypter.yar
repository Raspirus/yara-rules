rule RUSSIANPANDA_Truecrypt_Crypter : FILE
{
	meta:
		description = "Detects TrueCrypt crypter"
		author = "RussianPanda"
		id = "3ecf9c2f-6205-5e55-83a5-2b4e3ba89f07"
		date = "2024-01-06"
		modified = "2024-01-06"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/TrueCrypt/truecrypt_crypter.yar#L1-L27"
		license_url = "N/A"
		hash = "167637397fb45ea19bafcf208d8f27dceec82caa7ab19d40ecdb08eb1b7d4f60"
		logic_hash = "68612c68053e9fb81d9616c04b04ac2e2cb685f3b7ed71f8b31e8f22e3a539e7"
		score = 75
		quality = 81
		tags = "FILE"

	strings:
		$s1_crpt1 = {77 69 6E 65 5F 67 65 74}
		$s2_crpt1 = {49 3B 66 10 76}
		$s2_crpt2 = {3B 55 48 89 E5 48 83 EC 10 90 8B 0D [22] E8 [3] FF}
		$s3_crpt1 = {49 3B 66 10 76 43}
		$s3_crpt2 = {55 48 89 E5 48 83 EC 10 [5] E8 [4] 48 85 FF 75 18}
		$s4_crpt1 = {40 C0 EE 04 [16] 48 83}
		$s4_crpt2 = {FA 20 [0-22] 48 83 FE 20}
		$a_crpt = {61 2E 6F 75 74 2E 65 78 65 00 5F 63 67}
		$s_crpt = {6F 5F 64 75 6D 6D 79 5F 65 78 70 6F 72 74}

	condition:
		uint16(0)==0x5A4D and $s1_crpt1 and $s2_crpt1 and $s2_crpt2 and $s3_crpt1 and $s3_crpt2 and $s4_crpt1 and $s4_crpt2 and $a_crpt and $s_crpt and filesize <7MB
}