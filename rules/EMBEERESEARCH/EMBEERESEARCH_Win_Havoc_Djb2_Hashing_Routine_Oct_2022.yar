
rule EMBEERESEARCH_Win_Havoc_Djb2_Hashing_Routine_Oct_2022 : FILE
{
	meta:
		description = "No description has been set in the source file - EmbeeResearch"
		author = "embee_research @ HuntressLabs"
		id = "cde3e14f-0671-5bcf-93e8-e0a0af9b462c"
		date = "2022-10-11"
		modified = "2023-10-18"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/2022/win_havoc_djb2_hashing_routine_oct_2022.yar#L1-L24"
		license_url = "N/A"
		logic_hash = "9f645480c3d78153186a247440739a1d2e627ec64a4225083bd8db4ad9bd5ef3"
		score = 75
		quality = 75
		tags = "FILE"
		vendor = "Huntress Research"

	strings:
		$dll = {b8 05 15 00 00 0f be 11 48 ff c1 84 d2 74 07 6b c0 21 01 d0 eb ef}
		$shellcode = {41 80 f8 60 76 04 41 83 e8 20 6b c0 21 45 0f b6 c0 49 ff c1 44 01 c0 eb c4}

	condition:
		( any of them ) and ( uint16(0)==0x5a4d or uint16(0)==0x00e8 or uint16(0)==0x4856)
}