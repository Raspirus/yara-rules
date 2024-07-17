rule MALPEDIA_Win_Sanny_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "de370068-b36d-54a3-8d87-5388d41e6079"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sanny"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.sanny_auto.yar#L1-L125"
		license_url = "N/A"
		logic_hash = "d17095442c6476759b49de20e09af803b9389d5106c74ad1d4cc2616aa104b23"
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
		$sequence_0 = { 51 8bcb e8???????? 8b5310 68???????? 8d442a08 }
		$sequence_1 = { 8b842430060000 8d742410 8d5901 b987000000 53 81ec1c020000 8bfc }
		$sequence_2 = { ebd3 53 55 56 57 }
		$sequence_3 = { 52 68???????? 56 e8???????? 8b44244c }
		$sequence_4 = { 8bc2 c1c60a 03f1 f7d0 0bc6 33c1 }
		$sequence_5 = { ae 40 00bcae4000e0ae 40 0023 d18a0688078a }
		$sequence_6 = { 55 68???????? 55 e8???????? 8b4c2424 83c410 55 }
		$sequence_7 = { 663918 747f 668b11 6683fa41 720c }
		$sequence_8 = { f3ab 8b0d???????? aa 898c2408010000 b906000000 33c0 8dbc240d010000 }
		$sequence_9 = { 8b44241c 8d9424dc000000 52 50 ffd5 b925000000 33c0 }

	condition:
		7 of them and filesize <253952
}