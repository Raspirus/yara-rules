
rule MALPEDIA_Win_Blackenergy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "5db0ecdd-a93d-527c-8567-cf3a04744f9e"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackenergy"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.blackenergy_auto.yar#L1-L130"
		license_url = "N/A"
		logic_hash = "0197d7c7455032dc4a706fe02d56c8be876c2f6b4f29a6658284a54a2993239d"
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
		$sequence_0 = { bb01000000 eb02 03d8 8bc2 e9???????? 8b4df4 014dd8 }
		$sequence_1 = { 39750c 740c 56 56 ff7508 ff550c }
		$sequence_2 = { 8b7df4 8b75f0 8b4d08 f3a4 a1???????? 33c9 3bc1 }
		$sequence_3 = { e8???????? 2bc6 3bc7 760f 6bd20a 47 e8???????? }
		$sequence_4 = { 0f848f000000 53 8d45f0 50 8d45d8 50 }
		$sequence_5 = { 58 e8???????? 85c0 75ae 5e 5f c9 }
		$sequence_6 = { 85c0 7441 8b5dc8 8b5b28 85db 7427 8b4de4 }
		$sequence_7 = { 33f6 56 6810000002 6a03 56 6a01 6800000080 }
		$sequence_8 = { 8b583c 03d8 895dc8 8b4334 8945e0 33f6 46 }
		$sequence_9 = { 50 ff15???????? 50 ff5508 6a02 }

	condition:
		7 of them and filesize <98304
}