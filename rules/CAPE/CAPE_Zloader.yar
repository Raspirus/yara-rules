rule CAPE_Zloader : FILE
{
	meta:
		description = "Zloader Payload"
		author = "kevoreilly, enzok"
		id = "ce0662b4-c615-5b87-b5c1-173f90a97db2"
		date = "2024-05-06"
		modified = "2024-05-06"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Zloader.yar#L1-L18"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		hash = "adbd0c7096a7373be82dd03df1aae61cb39e0a155c00bbb9c67abc01d48718aa"
		logic_hash = "a94efd87c69146cf5771341974e5abe789445d67dde3e045e1b87d3131539ff9"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Zloader Payload"

	strings:
		$rc4_init = {31 [1-3] 66 C7 8? 00 01 00 00 00 00 90 90 [0-5] 8? [5-90] 00 01 00 00 [0-15] (74|75)}
		$decrypt_conf = {83 C4 04 84 C0 74 5? E8 [4] E8 [4] E8 [4] E8 [4] ?8 [4] ?8 [4] ?8}
		$decrypt_conf_1 = {48 8d [5] [0-6] e8 [4] 48 [3-4] 48 [3-4] 48 [6] E8}
		$decrypt_conf_2 = {48 8d [5] 4? [5] e8 [4] 48 [3-4] 48 8d [5] E8 [4] 48}
		$decrypt_key_1 = {66 89 C2 4? 8D 0D [3] 00 4? B? FC 03 00 00 E8 [4] 4? 83 C4 [1-2] C3}
		$decrypt_key_2 = {48 8d 0d [3] 00 66 89 ?? 4? 89 F0 4? [2-5] E8 [4-5] 4? 83 C4}
		$decrypt_key_3 = {48 8d 0d [3] 00 e8 [4] 66 89 [3] b? [4] e8 [4] 66 8b}

	condition:
		uint16(0)==0x5A4D and 1 of ($decrypt_conf*) and (1 of ($decrypt_key*) or $rc4_init)
}