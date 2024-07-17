rule MALPEDIA_Win_Xbtl_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "7372571c-d52e-5b5b-bd42-81e7e356cc7e"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xbtl"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.xbtl_auto.yar#L1-L130"
		license_url = "N/A"
		logic_hash = "b45bdfe7ddb3c3bebb25f685acba4274921aebf8fbd081dea272d3bf592a2a7b"
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
		$sequence_0 = { ffd7 50 ffd3 8bd8 85f6 7406 8d45e8 }
		$sequence_1 = { 99 8bd8 8bc1 99 33f6 0bf0 3135???????? }
		$sequence_2 = { 8d45ec 8d95f0fdffff e8???????? 8b85d4fdffff 56 56 6a03 }
		$sequence_3 = { 85d2 782a 895dfc 8b4d08 0fb63c0a 8b460c 0345fc }
		$sequence_4 = { 0fb67808 89948dc0feffff 0fb65007 c1e208 0bd7 }
		$sequence_5 = { 83c41c 8d4c2410 51 ffd7 8b442434 8b4c2428 8b1d???????? }
		$sequence_6 = { 8bd6 897c2420 2bd0 0fb708 66890c02 83c002 }
		$sequence_7 = { 03048de0c04200 eb02 8bc2 f6402480 7417 e8???????? c70016000000 }
		$sequence_8 = { 81e600ff00ff c1c208 81e2ff00ff00 0bf2 897018 8b491c }
		$sequence_9 = { 8b5708 40 83c410 894704 3bc2 7e16 8d0412 }

	condition:
		7 of them and filesize <401408
}