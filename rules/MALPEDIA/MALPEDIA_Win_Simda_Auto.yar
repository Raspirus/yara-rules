
rule MALPEDIA_Win_Simda_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "be795d70-d5c5-5e96-885a-c6d393925d47"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.simda"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.simda_auto.yar#L1-L114"
		license_url = "N/A"
		logic_hash = "3de0f7a52fa615dd54916d8a958f210fe06f4ad101457fb659a131786ec59f6f"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 50 c745fc04010000 a4 e8???????? }
		$sequence_1 = { 3bce 8945f4 1bc0 40 57 895dfc }
		$sequence_2 = { c7049f00000000 75f6 8b0f 894d08 }
		$sequence_3 = { 760d 8b7d08 83c704 8d4eff 33c0 }
		$sequence_4 = { c1e110 0b4df4 03d6 83ceff 2bca }
		$sequence_5 = { 8b0d???????? 8945d4 a1???????? 8955dc 0fb615???????? }
		$sequence_6 = { c1eb10 3bce 7601 4b c1ef10 }
		$sequence_7 = { 83c408 85c0 74e4 6a0a 6a00 56 c60000 }
		$sequence_8 = { 8bd1 c1ea10 8955ec 8bf8 }
		$sequence_9 = { 41 eb08 83c102 eb03 83c103 }

	condition:
		7 of them and filesize <1581056
}