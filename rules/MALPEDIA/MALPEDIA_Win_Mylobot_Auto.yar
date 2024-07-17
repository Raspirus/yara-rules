rule MALPEDIA_Win_Mylobot_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "7a067cd7-af50-5d95-bc8a-c729265f1a45"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mylobot"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.mylobot_auto.yar#L1-L164"
		license_url = "N/A"
		logic_hash = "e9a5b8dbe1c5cc719187453536536d6ca11df9a61a8a5853882ca3075e6106f0"
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
		$sequence_0 = { ff5014 56 6a00 50 8947f8 }
		$sequence_1 = { 89442414 75c7 eb02 33f6 85f6 741c }
		$sequence_2 = { 0f8344030000 8b0c83 8b442428 3bc8 0f823e020000 03442418 }
		$sequence_3 = { 83c41c 2b4734 7409 50 53 e8???????? }
		$sequence_4 = { 898108010000 8d442414 50 68???????? }
		$sequence_5 = { 51 ff742410 50 8d84248c020000 50 }
		$sequence_6 = { a1???????? 53 ff507c 8bf8 85ff 0f8491000000 8d442410 }
		$sequence_7 = { 81eccc000000 8b450c 53 56 57 8b00 }
		$sequence_8 = { 75cc 80bdfcfdffff01 0f8581000000 68???????? ff15???????? }
		$sequence_9 = { c785d4fdffff28010000 ff15???????? 8d8dd4fdffff 8bf8 }
		$sequence_10 = { 2bc2 8bc8 8bc3 8d7801 }
		$sequence_11 = { 83bd48ffffff00 0f85e9000000 807dda01 0f95c0 }
		$sequence_12 = { 7857 8b07 85c0 7462 }
		$sequence_13 = { ffd3 68???????? 8d742414 e8???????? 83c404 85c0 }
		$sequence_14 = { 897df4 3bc7 743d 8d55f4 }
		$sequence_15 = { 8bf0 81fed0040000 750e 8b4718 50 57 }

	condition:
		7 of them and filesize <8028160
}