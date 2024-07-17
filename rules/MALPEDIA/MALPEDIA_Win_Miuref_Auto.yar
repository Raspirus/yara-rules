rule MALPEDIA_Win_Miuref_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "34f2a1cb-9745-52c8-a75d-06d5cdb25bcd"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.miuref"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.miuref_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "0abc04edb362ffc2e411d61d44a4ba6937064194bb7ee145b0929a61d91bcae4"
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
		$sequence_0 = { 59 59 8945fc 85f6 760e 803c072e 7418 }
		$sequence_1 = { ff15???????? 50 e8???????? ff750c 8906 50 e8???????? }
		$sequence_2 = { 8bf0 8d7df0 a5 a5 a5 83c418 a5 }
		$sequence_3 = { 6a02 ff35???????? e8???????? 8bf0 83c40c 85f6 7412 }
		$sequence_4 = { 8d8300010000 ff75fc 50 e8???????? 68???????? 8d45f8 50 }
		$sequence_5 = { 8b4124 83f801 7514 ff7514 ff7510 ff750c }
		$sequence_6 = { 7509 0fb74e06 663bcf 7507 33c0 e9???????? }
		$sequence_7 = { e8???????? 50 ff35???????? e8???????? 83c43c e9???????? 55 }
		$sequence_8 = { 8d45d8 50 a5 e8???????? 83c408 8bf0 8bfc }
		$sequence_9 = { 53 53 ff15???????? 50 a3???????? e8???????? 59 }

	condition:
		7 of them and filesize <180224
}