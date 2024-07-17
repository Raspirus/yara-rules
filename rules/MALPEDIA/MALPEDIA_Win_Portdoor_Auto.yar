
rule MALPEDIA_Win_Portdoor_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "84ef053f-8b45-5899-91c4-5c0973d7e3db"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.portdoor"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.portdoor_auto.yar#L1-L124"
		license_url = "N/A"
		logic_hash = "23b6dfc496aede71e92bc63441565950d5591602bef8ef2eba1715ff0ea58fc2"
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
		$sequence_0 = { 50 e8???????? 83f8ff 8906 0f95c0 eb2f 807e5100 }
		$sequence_1 = { 50 8d85fcf3ffff 50 e8???????? 8bf0 }
		$sequence_2 = { ff5718 8903 6a04 59 8d4102 33d2 }
		$sequence_3 = { 8945a8 eb04 8365a800 8b45a8 894590 834dfcff 8b4590 }
		$sequence_4 = { 50 8b8528e5ffff 0f94c1 898d3ce5ffff 8b8d24e5ffff 8b0485b80f0210 ff3401 }
		$sequence_5 = { 894224 6689424c 894248 88424e 8a01 88040b }
		$sequence_6 = { 7e21 8b450c 6a00 2bc6 }
		$sequence_7 = { 51 51 8d45f8 895df8 }
		$sequence_8 = { e8???????? 8bf8 b8eeff0000 59 668907 8b450c 885f02 }
		$sequence_9 = { e8???????? a1???????? 33c5 8945fc 53 8b5d08 8d85fdfbffff }

	condition:
		7 of them and filesize <297984
}