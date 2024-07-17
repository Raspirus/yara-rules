rule MALPEDIA_Win_Vawtrak_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "b724e7c8-fa8b-5ecb-9091-2adfef543aee"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vawtrak"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.vawtrak_auto.yar#L1-L212"
		license_url = "N/A"
		logic_hash = "2420d7270c56567b74aa80afdfcc3b5893cd81eeb0dabc0a53855a9b85be220c"
		score = 75
		quality = 73
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
		$sequence_0 = { 6a01 ff35???????? 6a04 6a01 50 ff15???????? 85c0 }
		$sequence_1 = { 6a00 6a00 e8???????? 50 ff15???????? }
		$sequence_2 = { 837d1040 752d 8b4d04 e8???????? 85c0 }
		$sequence_3 = { 8b4d08 e8???????? 85c0 7415 ff15???????? 50 }
		$sequence_4 = { ba00ff0000 8bc1 23c2 3bc2 }
		$sequence_5 = { 750f 33c9 e8???????? 85c0 7404 }
		$sequence_6 = { b8ff0f0000 6623e8 b800400000 660be8 }
		$sequence_7 = { 6a08 68???????? 56 ffd7 85c0 }
		$sequence_8 = { 50 ff15???????? a3???????? 85c0 74e7 }
		$sequence_9 = { 7528 68???????? ff15???????? 85c0 7504 33c0 }
		$sequence_10 = { 59 57 8bf0 ff15???????? 8bc6 }
		$sequence_11 = { e8???????? 33d2 b9ff3f0000 f7f1 }
		$sequence_12 = { 8bc6 8703 3bc6 74f8 }
		$sequence_13 = { 56 6a04 53 57 }
		$sequence_14 = { 7705 80ea61 eb0a 8d42bf }
		$sequence_15 = { 03c1 8b4d14 8901 33c0 40 }
		$sequence_16 = { e9???????? 8ac1 c1e904 c0e004 }
		$sequence_17 = { 8ac8 240f 80e1f0 80c110 32c8 }
		$sequence_18 = { 3c41 7c11 3c46 7f0d }
		$sequence_19 = { 48397c2430 7505 bb01000000 8bc3 }
		$sequence_20 = { 4885c0 7440 ff15???????? 488b0b 33ff 3db7000000 }
		$sequence_21 = { 0f84ff000000 3d00010000 7320 488b0b }
		$sequence_22 = { 420fb61408 8bc1 ffc1 42881408 }

	condition:
		7 of them and filesize <1027072
}