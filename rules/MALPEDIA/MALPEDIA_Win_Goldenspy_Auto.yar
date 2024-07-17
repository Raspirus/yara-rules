rule MALPEDIA_Win_Goldenspy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "2db85832-8503-5134-9cf2-a79f16f8ed47"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.goldenspy"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.goldenspy_auto.yar#L1-L130"
		license_url = "N/A"
		logic_hash = "45ec0195c1eec86aab8f23405836b0cab0b81ad642d99b8dc40b2feb153827cd"
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
		$sequence_0 = { 0f87e4000000 e9???????? 83c754 837f1000 740f 68???????? 8bcf }
		$sequence_1 = { 83c0fc 83f81f 0f8777060000 52 51 e8???????? 83c408 }
		$sequence_2 = { 8b7608 807e0d00 74a8 8b4de8 8b5de4 }
		$sequence_3 = { e8???????? 8b551c 83fa10 0f82b8fcffff 8b4d08 42 8bc1 }
		$sequence_4 = { e8???????? 51 68???????? 8bcb e8???????? 8b83c8000000 }
		$sequence_5 = { 8d4dd8 6a1a 68???????? c745e800000000 c745ec0f000000 c645d800 e8???????? }
		$sequence_6 = { 57 68???????? e8???????? 8d47ff 83c408 83f804 }
		$sequence_7 = { 75f2 8b5308 8bf2 8b7b14 0f1f00 8a02 42 }
		$sequence_8 = { ff75e4 ff461c 8d4628 50 e8???????? 897e30 c7463400000000 }
		$sequence_9 = { 8b85f8feffff 8b4004 c78405f8feffffb4e24600 8b85f8feffff 8b4804 8d41b0 89840df4feffff }

	condition:
		7 of them and filesize <1081344
}