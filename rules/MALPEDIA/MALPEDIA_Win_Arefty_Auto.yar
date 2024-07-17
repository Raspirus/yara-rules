rule MALPEDIA_Win_Arefty_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "290417d3-5ee5-5229-8624-fd994b33b5b6"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.arefty"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.arefty_auto.yar#L1-L119"
		license_url = "N/A"
		logic_hash = "f5f9e554cdcd0132916bd1281d9476767533aa9af2658a9193107a622555119f"
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
		$sequence_0 = { 57 e8???????? 83c404 83fbff 7407 53 }
		$sequence_1 = { 50 53 ff15???????? 680000a000 e8???????? }
		$sequence_2 = { 680000a000 57 53 ff15???????? 85c0 }
		$sequence_3 = { 680000a000 57 53 ff15???????? }
		$sequence_4 = { 57 e8???????? 83c404 83fbff 7407 53 ff15???????? }
		$sequence_5 = { ff15???????? 680000a000 e8???????? 8bf8 }
		$sequence_6 = { 0fb6041e 50 8b07 68???????? 6a03 8d04b0 }
		$sequence_7 = { 8b07 68???????? 6a03 8d04b0 50 e8???????? 46 }
		$sequence_8 = { 50 53 ff15???????? 680000a000 e8???????? 8bf8 83c404 }
		$sequence_9 = { 50 53 ff15???????? 680000a000 }

	condition:
		7 of them and filesize <237568
}