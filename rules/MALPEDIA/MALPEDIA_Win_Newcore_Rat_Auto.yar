
rule MALPEDIA_Win_Newcore_Rat_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "665a19c1-0b9c-5837-8284-a9e9fed7fabd"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.newcore_rat"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.newcore_rat_auto.yar#L1-L129"
		license_url = "N/A"
		logic_hash = "bc0ab135cc137a5ffe441affd5712e460cc93f003c5dd205f806c56bc27b56a3"
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
		$sequence_0 = { 8b08 8b11 50 8b4204 ffd0 8d4c2414 e8???????? }
		$sequence_1 = { 898670300000 e8???????? 5f 5d b801000000 }
		$sequence_2 = { 51 8d4c243c e8???????? 8d4c2414 e8???????? 8b542448 52 }
		$sequence_3 = { 50 8d4c245e 51 6689442460 e8???????? 83c40c 6a30 }
		$sequence_4 = { 6a00 6a00 8d542478 52 6a00 ff15???????? 85c0 }
		$sequence_5 = { 8b442450 e9???????? 6830020000 8d442458 6a00 50 }
		$sequence_6 = { 8b8610100000 85c0 740d 50 ffd7 c7861010000000000000 }
		$sequence_7 = { 5b c21000 8d9344020000 68???????? 52 e8???????? 8bf0 }
		$sequence_8 = { 83c40c 03f9 014c2414 eb04 8b5c240c 014c242c b81f85eb51 }
		$sequence_9 = { 68???????? 8d9424ac060000 e8???????? 83c408 53 8d8c24a8060000 }

	condition:
		7 of them and filesize <581632
}