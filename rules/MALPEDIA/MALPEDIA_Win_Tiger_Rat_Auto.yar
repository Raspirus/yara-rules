rule MALPEDIA_Win_Tiger_Rat_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "c2ea69b5-54d0-5c61-bb49-4f65b838d0af"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tiger_rat"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.tiger_rat_auto.yar#L1-L165"
		license_url = "N/A"
		logic_hash = "bed3ce3d252a7d616792a16e358ffda1357857c1fa2b5862a7f71cbabe456650"
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
		$sequence_0 = { 4883c128 4889742448 48897c2450 ff15???????? }
		$sequence_1 = { 0f11400c 488b4e28 488b5618 488b01 ff5010 }
		$sequence_2 = { 4883c108 e8???????? 4d8b4618 41b901000000 }
		$sequence_3 = { 33d2 41b80c000100 488bd8 e8???????? 4c63442430 488b4f08 }
		$sequence_4 = { 4883c108 413bc0 7cef eb06 4898 }
		$sequence_5 = { 4883c110 e8???????? 896e30 381f }
		$sequence_6 = { 4883c10c e8???????? 488b4f28 488b5718 }
		$sequence_7 = { 4883c110 48c741180f000000 33ed 48896910 408829 48c746500f000000 }
		$sequence_8 = { 7ce0 488bce ff15???????? 8b0d???????? }
		$sequence_9 = { ff15???????? 488bc8 ff15???????? ba0a000000 }
		$sequence_10 = { 0b05???????? 8905???????? ff15???????? ff15???????? b9e8030000 8bd8 }
		$sequence_11 = { 4c2bf3 8905???????? 493bf7 0f83c8000000 48896c2478 4c896c2430 41bd00f00000 }
		$sequence_12 = { c705????????02000000 488905???????? 488d0556eb0100 48891d???????? 488905???????? 33c0 488905???????? }
		$sequence_13 = { 8b05???????? 4d8bf4 2305???????? 4c03fe 4c2bf3 8905???????? }
		$sequence_14 = { 4c8d35046c0100 49833cde00 7407 b801000000 eb5e }
		$sequence_15 = { 8bd8 e8???????? 2bc3 3d70170000 7cf2 e8???????? }

	condition:
		7 of them and filesize <557056
}