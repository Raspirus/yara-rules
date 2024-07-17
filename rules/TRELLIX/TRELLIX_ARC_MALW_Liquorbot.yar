rule TRELLIX_ARC_MALW_Liquorbot : MALWARE FILE
{
	meta:
		description = "Rule to detect LiquorBot malware"
		author = "Marc Rivero | McAfee ATR Team"
		id = "73898df8-b5eb-50ac-a2fe-ef9233c251c5"
		date = "2020-08-19"
		modified = "2020-08-19"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_liquorbot.yar#L1-L23"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "2448e3ede809331b2370fe9d42d603ad6508be6531a1a8764e0e0621867b6e89"
		score = 75
		quality = 70
		tags = "MALWARE, FILE"
		rule_version = "v1"
		malware_type = "malware"
		malware_family = "Botnet:W32/LiquorBot"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		hash1 = "5b2a9cbda99ed903f75c3b37f0a6b1b9f6c39671a76ed652f3ddba117fd43bc9"

	strings:
		$pattern = { 7F454C4602010100000000000000000002003E0001000000605A4600000000004000000000000000700200000000000000000000400038000A0040001B00090006000000040000004000000000000000400040000000000040004000000000003002000000000000300200000000000000100000000000000300000004000000E00F000000000000E00F400000000000E00F40000000000020000000000000002000000000000000010000000000000004000000040000007C0F0000000000007C0F4000000000007C0F400000000000640000000000000064000000000000000400000000000000010000000500000000000000000000000000400000000000000040000000000040FB29000000000040FB2900000000000010000000000000010000000400000000002A000000000000006A000000000000006A0000000000E4492C0000000000E4492C000000000000100000000000000100000006000000005056000000000000509600000000000050960000000000E014040000000000681307000000000000100000000000000200000006000000405156000000000040519600000000004051960000000000300100000000000030010000000000000800000000000000070000000400000000000000000000000000000000000000000000000000000000000000000000000800000000000000080000000000000051E574640600000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000080150465002A00000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000010000000600000000000000001040000000000000100000000000001FE9290000000000000000000000000010000000000000000000000000000000F000000001000000060000000000000020F969000000000020F929000000000020020000000000000000000000000000100000000000000010000000000000007000000001000000020000000000000000006A000000000000002A0000000000A678110000000000000000000000000020000000000000000000000000000000E0000000040000000200000000000000A8787B0000000000A8783B000000000018000000000000000B0000000000000008000000000000001800000000000000E6000000040000000200000000000000C0787B0000000000C0783B000000000018030000000000000B0000000200000008000000000000001800000000000000F5000000FF }

	condition:
		uint16(0)==0x457f and all of them
}