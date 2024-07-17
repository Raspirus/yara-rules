rule MALPEDIA_Win_Shifu_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "b2b85e64-d954-5aeb-b02a-9d97cb3ba3ee"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shifu"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.shifu_auto.yar#L1-L129"
		license_url = "N/A"
		logic_hash = "fa5868e6742fc467c77c9f2e2fa5062fd3f24b48dd60ea0ece307848b06e5759"
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
		$sequence_0 = { 85c0 740d 57 6a1b ba???????? }
		$sequence_1 = { 6a24 ff7508 ffd6 53 8d45f0 50 }
		$sequence_2 = { 83651800 8d941a00010000 895508 8b5510 0fbe1410 89550c 85c9 }
		$sequence_3 = { 740c e8???????? 8325????????00 8d85fcfeffff e8???????? }
		$sequence_4 = { 50 ff75f4 ff15???????? 85c0 7511 ff75f0 8d443701 }
		$sequence_5 = { 668985a2fcffff b8170b0000 66898578fcffff 6a14 58 6689857afcffff 8b4348 }
		$sequence_6 = { 83c102 836d0c02 eb2d 8bd9 8b4f2c 2bd8 035de8 }
		$sequence_7 = { 8975e4 6a0c 58 e8???????? 8965e8 8bfc 3bfe }
		$sequence_8 = { 33c0 5e c9 c20c00 55 8bec 85c9 }
		$sequence_9 = { 56 8d85e8feffff 53 50 ff15???????? 8d85e8feffff 83c410 }

	condition:
		7 of them and filesize <344064
}