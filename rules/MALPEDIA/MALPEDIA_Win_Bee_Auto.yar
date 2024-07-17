rule MALPEDIA_Win_Bee_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "cf854a1b-a3fa-5497-9620-9eb04ca1acba"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bee"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.bee_auto.yar#L1-L124"
		license_url = "N/A"
		logic_hash = "d1087a1b19c31419362e6bad586912e9950c25554053241c2a8ca3db38a0bc54"
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
		$sequence_0 = { 0f8326010000 8bce d1e9 ba49922409 2bd1 3bd6 7304 }
		$sequence_1 = { 83c404 89742418 c644244806 3bf3 741d 8b542414 }
		$sequence_2 = { 668944241c 52 8d44241c 50 8d4c2438 c744242000000000 e8???????? }
		$sequence_3 = { e8???????? 8b542424 56 6a00 52 e8???????? 8b7c2434 }
		$sequence_4 = { 8d8424a4000000 8a10 3a11 751a 3ad3 7412 }
		$sequence_5 = { 8bf9 80bfd800000000 754e 6a11 6a02 6a02 }
		$sequence_6 = { e8???????? 8d0cb6 c1e104 03c8 89470c 894710 }
		$sequence_7 = { 8bc3 8bcf e8???????? 2bf7 b867666666 f7ee }
		$sequence_8 = { e8???????? 83c414 8b45fc ff34c5e4314200 }
		$sequence_9 = { 64a300000000 8b6c2420 33db 895d04 885d0c }

	condition:
		7 of them and filesize <394240
}