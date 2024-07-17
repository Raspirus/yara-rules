rule MALPEDIA_Win_Maktub_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "e3bef5b1-ffc5-599d-9917-312a2370b890"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.maktub"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.maktub_auto.yar#L1-L203"
		license_url = "N/A"
		logic_hash = "e077a57d767e9de98d639131f563ec23078961a903d866aaf47969e99e6c3d2f"
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
		$sequence_0 = { ffd0 f7d8 1bc0 f7d8 8be5 }
		$sequence_1 = { c7450c00000000 50 6a01 56 }
		$sequence_2 = { ff30 8b86a4000000 ffd0 8b75b4 }
		$sequence_3 = { ff30 8b83a4000000 ffd0 8b75d4 }
		$sequence_4 = { ff7508 ffd7 50 ffd6 53 8b5d08 6af4 }
		$sequence_5 = { ff30 8b8690000000 6a00 ffd0 }
		$sequence_6 = { ff30 8b4704 6a00 56 ffd0 85c0 }
		$sequence_7 = { c74508???????? e9???????? 50 ff15???????? 85c0 7f1e a1???????? }
		$sequence_8 = { ff7004 ff30 e8???????? 8bc7 5f 5e }
		$sequence_9 = { f8 39dc f5 f7de }
		$sequence_10 = { f8 57 c64424084b 88442404 }
		$sequence_11 = { f8 60 0145e0 f8 }
		$sequence_12 = { f8 50 55 660fa3d5 }
		$sequence_13 = { 8d4f0c e8???????? 8d4de8 e8???????? }
		$sequence_14 = { 8d4f04 8b01 ff7508 ff5010 8bd8 }
		$sequence_15 = { f8 3a07 6868c51b01 8d7f01 }
		$sequence_16 = { 8d4f04 8b45f4 8b31 2bc2 }
		$sequence_17 = { 8d4f04 e8???????? 8d5608 8d4f08 }
		$sequence_18 = { 8d4f08 e8???????? 8d560c 8d4f0c e8???????? }
		$sequence_19 = { 8d4f0c e8???????? 5f 5e 5d c20400 }
		$sequence_20 = { f8 12644a00 40 d4b5 }
		$sequence_21 = { 8d4f10 50 e8???????? 8d45f8 }

	condition:
		7 of them and filesize <3063808
}