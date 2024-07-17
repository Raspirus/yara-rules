rule MALPEDIA_Win_Banjori_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "0d7b2a6e-e2ca-5160-9081-9a7cfdf5e1be"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.banjori"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.banjori_auto.yar#L1-L133"
		license_url = "N/A"
		logic_hash = "9dcfb5d77d585c9251303d49a0603c551cff0efcfccd66cc7c87519a0e64ecdd"
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
		$sequence_0 = { 6800010000 e8???????? 8945f4 81f9000c0000 7308 e8???????? 8945f0 }
		$sequence_1 = { 50 ff15???????? ffb5a0feffff e8???????? 53 53 53 }
		$sequence_2 = { 68???????? ff75fc ff15???????? 53 ff75fc ff15???????? 68???????? }
		$sequence_3 = { ff750c 53 53 53 53 ff7508 ff35???????? }
		$sequence_4 = { 78e1 8945e8 eb18 8d85aafeffff 50 ff75e8 ff15???????? }
		$sequence_5 = { 85c0 7539 68???????? e8???????? 85c0 752b }
		$sequence_6 = { 6802000080 e8???????? 85c0 0f85fe000000 895df0 8d45f0 50 }
		$sequence_7 = { 8945f4 8d45f8 50 6819000200 6a00 68???????? 6802000080 }
		$sequence_8 = { 50 ff35???????? e8???????? e9???????? c745f864000000 68???????? ff15???????? }
		$sequence_9 = { 6a10 8d45b4 50 ff75c4 ff15???????? 85c0 0f883a020000 }

	condition:
		7 of them and filesize <139264
}