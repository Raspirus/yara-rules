
rule MALPEDIA_Win_Remsec_Strider_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "5cf05a79-eeb6-5c58-8271-14cb9c81c326"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.remsec_strider"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.remsec_strider_auto.yar#L1-L115"
		license_url = "N/A"
		logic_hash = "69887265225a27114e8e9d83252b405933e8e0558a06ab3222eee20510a77720"
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
		$sequence_0 = { 74f7 8b4130 2dbc97e889 f7d8 1bc0 f7d0 }
		$sequence_1 = { 6a1a 58 6a10 8945e4 8945e8 58 }
		$sequence_2 = { c9 c20800 55 8bec b804000100 }
		$sequence_3 = { 85c9 74f7 8b4130 2dbc97e889 }
		$sequence_4 = { 6803010000 50 ff15???????? 83c414 8d45f0 50 }
		$sequence_5 = { 0d00000040 50 8d85e8fdffff 50 }
		$sequence_6 = { ebf5 8b432c ff30 68???????? }
		$sequence_7 = { 0510010000 68???????? 6803010000 50 }
		$sequence_8 = { ff772c ff15???????? 85c0 7512 ff15???????? 8bc8 }
		$sequence_9 = { 85ff 7415 83ff05 7410 68???????? 6a02 }

	condition:
		7 of them and filesize <344064
}