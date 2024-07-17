
rule MALPEDIA_Win_Flying_Dutchman_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "bcfa70ed-52d3-5ff6-98d2-54bf0fdb6694"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.flying_dutchman"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.flying_dutchman_auto.yar#L1-L128"
		license_url = "N/A"
		logic_hash = "395092a50a0edc892d45a5d410470e4cbf5a35f346d3d2f6d581d10febaed0cd"
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
		$sequence_0 = { 66890c02 83c002 6685c9 75f1 e9???????? 8b85e8feffff 83e800 }
		$sequence_1 = { 48 0f84f8000000 48 0f853d010000 83bd44fcffff06 7553 8b35???????? }
		$sequence_2 = { 8bec 51 56 6a18 e8???????? 33f6 }
		$sequence_3 = { 8d442430 50 89742438 895c2434 68???????? eb40 57 }
		$sequence_4 = { ff75f0 f3a5 ff75f4 ff15???????? ff75f4 8b35???????? ffd6 }
		$sequence_5 = { 3bfb 7531 6a14 e8???????? 8bf0 59 }
		$sequence_6 = { ff15???????? 3bc7 7504 33c0 eb1f 0fbf480a }
		$sequence_7 = { 0f8489000000 48 747f 2ddb030000 }
		$sequence_8 = { e8???????? 8be5 5d c20800 55 8bec 81eca8000000 }
		$sequence_9 = { 832600 83660400 83660800 c3 8b4b04 56 57 }

	condition:
		7 of them and filesize <276480
}