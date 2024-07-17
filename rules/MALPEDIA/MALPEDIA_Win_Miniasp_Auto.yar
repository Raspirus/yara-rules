rule MALPEDIA_Win_Miniasp_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a296e0dd-d471-5c91-a6b1-780906aaa535"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.miniasp"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.miniasp_auto.yar#L1-L129"
		license_url = "N/A"
		logic_hash = "9a4758ded83cb0970a2c1c85a01ff8f2f0263c333e1e2d45a290cc1db4a95dd4"
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
		$sequence_0 = { 8b45c0 898550ffffff 8b8550ffffff 40 89854cffffff 8b8550ffffff }
		$sequence_1 = { ff15???????? 85c0 751b c785c0fbffff10d84000 68???????? 8d85c0fbffff 50 }
		$sequence_2 = { 8b4508 0345f0 0fbe4002 83f841 7c15 8b4508 }
		$sequence_3 = { 747c 8b45f4 8945d8 8b45d8 40 8945d4 8b45d8 }
		$sequence_4 = { 83a564ffffff00 eb0b 1bc0 83d8ff 898564ffffff }
		$sequence_5 = { 6a00 ff75f8 e8???????? 83c40c 6804010000 6a00 }
		$sequence_6 = { 68???????? 8d85c0fbffff 50 e8???????? b001 5f 5e }
		$sequence_7 = { ff15???????? 85c0 7534 ff15???????? 3d882f0000 7427 ff75f8 }
		$sequence_8 = { 0f8516010000 8b45ec 8b00 8b4dec ff5020 8945f4 837df400 }
		$sequence_9 = { 8985ecfbffff 8b85ecfbffff 3b45fc 7728 6a01 68???????? 8b4508 }

	condition:
		7 of them and filesize <139264
}