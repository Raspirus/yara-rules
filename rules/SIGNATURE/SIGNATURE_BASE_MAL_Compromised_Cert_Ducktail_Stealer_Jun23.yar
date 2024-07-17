
rule SIGNATURE_BASE_MAL_Compromised_Cert_Ducktail_Stealer_Jun23 : FILE
{
	meta:
		description = "Detects binaries signed with compromised certificates used by DuckTail stealer - identified in June 2023"
		author = "dr4k0nia"
		id = "b491e1b6-42c4-58e9-8efa-19e697804f96"
		date = "2023-06-16"
		modified = "2023-08-12"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_ducktail_compromised_certs_jun23.yar#L2-L37"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9b7916700359d662e99003727f5293f5a937254ff265c3bc8bb8763e196daa0e"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "17c75f2d14af9f00822fc1dba00ccc9ec71fc50962e196d7e6f193f4b2ee0183"
		hash2 = "b3cfdb442772d07a7f037b0bb093ba315dfd1e79b0e292736c52097355495270"
		hash3 = "9afe013cae0167993a6a7ccd650eb1221a5ec163110565eb3a49a8b57949d4ee"

	strings:
		$sx1 = "AZM MARKETING COMPANY LIMITED" ascii fullword
		$sx2 = "CONG TY TNHH" ascii
		$sx3 = {43 C3 94 4E 47 20 54 59 20 54 4E 48 48 20}
		$sx4 = "CONG TY TRACH" ascii
		$se1 = {65 78 BE 85 2D 48 E3 3D 4E 48 B8 D4 73 F5 B7 60}
		$se2 = {1D 53 38 32 74 2B 58 37 87 C0 A2 53 32 F7 FB 06}
		$se3 = {00 BD 7B 85 B2 6A 69 C9 7D 6D 68 CC 95 67 34 C0 6B}
		$se4 = {06 5F 5C 57 0B D6 A7 98 92 FB B0 E6 34 61 3A 4D}
		$se5 = {41 55 3F 07 13 37 11 7A 99 B4 58 57}
		$se6 = {1E AA E4 CE E7 EE 89 FB 20 32 59 27 88 13 D8 53}
		$se7 = {56 DC DB 85 D4 89 F9 87 B2 D6 76 72}
		$se8 = {2D A4 50 57 C2 74 3C 1A 3C A4 93 7A}
		$se9 = {37 AE 95 F5 4C 8E 9B D0 B6 47 68 6A}
		$se10 = {3D C8 F5 3B 62 7A 34 07 AC 7E 01 00 13 87 A3 B3}
		$se11 = {01 C9 87 5A 5F A8 59 68 6D 34 17 C9}
		$se12 = {1B 35 19 E1 CD C2 6B 57 DA EE 06 C9}
		$se13 = {79 7D 0B 5E 22 AA 0F C7 A2 97 E6 48}
		$se14 = {57 9E 5C 89 B0 85 A7 96 B3 3C F3 19}

	condition:
		uint16(0)==0x5a4d and 1 of ($sx*) and 1 of ($se*)
}