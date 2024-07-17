
rule MALPEDIA_Win_Cryptowall_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "4b008ce5-4135-5555-ab2d-ce0ccd0475ff"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cryptowall"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.cryptowall_auto.yar#L1-L114"
		license_url = "N/A"
		logic_hash = "496e72f17aa4e054ce74cb3a6412cb731c4d48c85c6550891be7fb095dff5a0a"
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
		$sequence_0 = { 85c0 7504 33c0 eb21 0fb74d08 83f961 }
		$sequence_1 = { b979000000 66894de6 ba73000000 668955e8 }
		$sequence_2 = { e8???????? 83c408 8b0d???????? 898164010000 }
		$sequence_3 = { 55 8bec 51 837d0800 7441 837d0c00 }
		$sequence_4 = { 7d1f 6a09 6a00 e8???????? }
		$sequence_5 = { e8???????? 83c408 8b0d???????? 8901 68f2793618 }
		$sequence_6 = { 8b4508 668910 8b4d08 83c102 894d08 eb02 eba1 }
		$sequence_7 = { 668955e8 b874000000 668945ea b965000000 }
		$sequence_8 = { 7511 6aff 8b4508 50 }
		$sequence_9 = { 6a00 6a00 6a40 6a01 6a01 6880000000 }

	condition:
		7 of them and filesize <417792
}