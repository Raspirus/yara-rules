
rule ARKBIRD_SOLG_SP_Vault7_SIG_F_Nov_2020_1 : FILE
{
	meta:
		description = "Detect open-source PasswordReminder recovery tools used by Chinese APT in the Past"
		author = "Arkbird_SOLG"
		id = "0b65e333-16e2-57c3-84f0-5cd24c9d9593"
		date = "2020-11-30"
		modified = "2020-11-30"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-11-30/SP_Vault7_SIG_F_Nov_2020_1.yar#L1-L23"
		license_url = "N/A"
		logic_hash = "b03ffb433491b532d891f29aeb5b33c6578067f2f05845514a7bdc1e50f88a10"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "e6e17f2b2ce0ae07cf48654156b79ee90d330961456f731e84c94f50fe34f802"
		hash2 = "c224ee5bef42a45e84e0d5a409d8b4c3842b2a7ac3fe5006ee795e64e0778e6e"

	strings:
		$dbg1 = { 50 61 73 73 77 6f 72 64 52 65 6d 69 6e 64 65 72 20 69 73 20 75 6e 61 62 6c 65 20 74 6f 20 66 69 6e 64 20 57 69 6e 4c 6f 67 6f 6e 20 6f 72 20 79 6f 75 20 61 72 65 20 75 73 69 6e 67 20 4e 57 47 49 4e 41 2e 44 4c 4c 2e 0a }
		$dbg2 = { 54 68 65 20 65 6e 63 6f 64 65 64 20 70 61 73 73 77 6f 72 64 20 69 73 20 66 6f 75 6e 64 20 61 74 20 30 78 25 38 2e 38 6c 78 20 61 6e 64 20 68 61 73 20 61 20 6c 65 6e 67 74 68 20 6f 66 20 25 64 2e 0a }
		$dbg3 = { 50 61 73 73 77 6f 72 64 52 65 6d 69 6e 64 65 72 20 69 73 20 75 6e 61 62 6c 65 20 74 6f 20 66 69 6e 64 20 74 68 65 20 70 61 73 73 77 6f 72 64 20 69 6e 20 6d 65 6d 6f 72 79 2e 0a }
		$dbg4 = { 20 55 73 61 67 65 3a 20 25 73 20 44 6f 6d 61 69 6e 4e 61 6d 65 20 55 73 65 72 4e 61 6d 65 20 50 49 44 2d 6f 66 2d 57 69 6e 4c 6f 67 6f 6e 0a 0a }
		$dbg5 = { 54 68 65 20 6c 6f 67 6f 6e 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 69 73 3a 20 25 53 2f 25 53 2f 25 53 2e 0a }
		$dbg6 = { 54 68 65 20 57 69 6e 4c 6f 67 6f 6e 20 70 72 6f 63 65 73 73 20 69 64 20 69 73 20 25 64 20 28 30 78 25 38 2e 38 6c 78 29 2e 0a }
		$dbg7 = { 59 6f 75 20 6c 6f 67 67 65 64 20 6f 6e 20 61 74 20 25 64 2f 25 64 2f 25 64 20 25 64 3a 25 64 3a 25 64 0a }
		$dbg8 = { 54 68 65 20 68 61 73 68 20 62 79 74 65 20 69 73 3a 20 30 78 25 32 2e 32 78 2e 0a }
		$dbg9 = { 53 55 56 57 68 14 ?? 40 00 e8 17 0c 00 00 8b 6c 24 1c [1-4] 45 00 50 68 e0 ?? 40 00 e8 ?? ?? 00 00 83 c4 ?? e8 ?? 02 00 00 85 c0 75 1d e8 ?? 02 00 00 85 c0 75 14 68 b4 ?? 40 00 e8 ?? 0b 00 00 83 c4 04 33 c0 5f 5e 5d 5b }

	condition:
		uint16(0)==0x4d5a and filesize >50KB and 6 of them
}