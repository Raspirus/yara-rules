
rule MALPEDIA_Win_Cerber_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "1b1175b4-aaae-5323-bbb6-472b8daa3220"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cerber"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.cerber_auto.yar#L1-L101"
		license_url = "N/A"
		logic_hash = "90183139badfe5f943ec4dd7b3bc0305f6ea2215a75a5dc8603646346366cf36"
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
		$sequence_0 = { 4a 79f6 5f 8bc6 }
		$sequence_1 = { 85c0 750c 8b33 e8???????? 832300 eb0e 8b4dfc }
		$sequence_2 = { 33f9 8b88e0000000 894dd0 8b88e4000000 899864010000 8b5dd8 }
		$sequence_3 = { 4a 79e6 47 3b7d0c }
		$sequence_4 = { 51 53 56 8bf0 57 85f6 7508 }
		$sequence_5 = { 4a b800000080 83e904 eb02 }
		$sequence_6 = { 895df4 33c9 83fa08 0f9dc1 854df4 7515 }
		$sequence_7 = { 33f9 8b88e8feffff 234808 8998fc000000 8b5874 }

	condition:
		7 of them and filesize <573440
}