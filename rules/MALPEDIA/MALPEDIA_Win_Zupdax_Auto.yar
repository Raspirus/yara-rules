rule MALPEDIA_Win_Zupdax_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "0a0ddf15-919a-51b3-8d2b-36d56a66b11c"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zupdax"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.zupdax_auto.yar#L1-L118"
		license_url = "N/A"
		logic_hash = "b6e9bce8da2b32bfb52c3b6477d889790098710bc4ce9f32e2c7bd1bace10557"
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
		$sequence_0 = { 895e2c e8???????? 8b460c 83c404 3bc3 7419 }
		$sequence_1 = { 8b4c2408 8b7e10 51 e8???????? 8b560c 52 e8???????? }
		$sequence_2 = { 52 68???????? ff15???????? 8d442444 }
		$sequence_3 = { e8???????? 83c408 8b4618 50 895e24 895e28 895e2c }
		$sequence_4 = { 394c2414 765b 53 41 81e1ff000080 }
		$sequence_5 = { 4b 81cb00ffffff 43 0fb61403 30142f 47 }
		$sequence_6 = { 895710 8b4614 894e14 8b5718 894714 8b4618 895618 }
		$sequence_7 = { 2bc2 50 8d54241c 52 }
		$sequence_8 = { 46 8a1c06 881c01 881406 }
		$sequence_9 = { 8b4c2408 8b7e10 51 e8???????? }

	condition:
		7 of them and filesize <1032192
}