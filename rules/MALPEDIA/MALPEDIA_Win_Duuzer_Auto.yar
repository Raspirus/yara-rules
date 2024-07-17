rule MALPEDIA_Win_Duuzer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "df8c3768-3cdc-5b0e-a660-661bdb978bfa"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.duuzer"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.duuzer_auto.yar#L1-L145"
		license_url = "N/A"
		logic_hash = "13aac089d76bc4f63a9fe69893726cbd97eb78875b3161a00634aa641d0ec8d3"
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
		$sequence_0 = { 83f804 7408 83c8ff e9???????? }
		$sequence_1 = { 0145f0 1155f4 85c9 7533 }
		$sequence_2 = { 57 4154 4155 4881ec88080000 488b05???????? 4833c4 }
		$sequence_3 = { 00f4 c640001c c740008a460323 d188470383ee }
		$sequence_4 = { 56 57 b830910000 e8???????? }
		$sequence_5 = { 56 57 b8a0010100 e8???????? }
		$sequence_6 = { 56 57 488dac2410fcffff 4881ecf0040000 }
		$sequence_7 = { 01442410 3bfb 75c4 8b4630 }
		$sequence_8 = { 57 4154 4883ec20 448be2 }
		$sequence_9 = { 57 4154 4155 4156 4883ec30 488b05???????? }
		$sequence_10 = { 014dec 83bf8400000000 7708 398780000000 }
		$sequence_11 = { 57 4154 4155 4883ec20 33f6 488bd9 }
		$sequence_12 = { 014dec 66837dec00 0f8efc010000 0fbf45ec }
		$sequence_13 = { 00e0 3541000436 41 0023 }
		$sequence_14 = { 010b 014e4c 014e48 014e54 }

	condition:
		7 of them and filesize <491520
}