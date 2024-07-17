
rule MALPEDIA_Win_Swen_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "7f9f6459-0c0a-509f-9c87-8a68bae77e34"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.swen"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.swen_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "6a4f1002b8a4868bbe8661a8400f2e2886c507211772c905c6406fbef250b4fb"
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
		$sequence_0 = { ab 8d85a8fcffff 50 8d8564fcffff 50 56 56 }
		$sequence_1 = { 6a05 59 be???????? 8dbd1cfeffff f3a5 66a5 }
		$sequence_2 = { 68b0040000 ff15???????? c9 c3 55 8bec 6aff }
		$sequence_3 = { 33c9 85c0 0f95c1 41 890d???????? 8b450c 3905???????? }
		$sequence_4 = { 59 59 50 8d8594fcffff 50 }
		$sequence_5 = { 0fbe4602 8d48df 83f951 7408 83c00a 83f85c 755f }
		$sequence_6 = { 53 6880000000 6a04 53 6a03 6800000040 8d85e4feffff }
		$sequence_7 = { e8???????? 8d85d8fdffff 50 8d8550ffffff 50 e8???????? 8d4603 }
		$sequence_8 = { 0f84b2000000 895de0 8b4de4 c1e902 8b45e0 3bc1 0f839e000000 }
		$sequence_9 = { 3bc3 7410 8d8d80feffff 2bc1 40 40 89857cfeffff }

	condition:
		7 of them and filesize <286720
}