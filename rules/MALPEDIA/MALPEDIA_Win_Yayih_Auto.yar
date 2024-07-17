rule MALPEDIA_Win_Yayih_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "ad6edea8-11c9-5fa2-96f2-3800b1bd4695"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yayih"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.yayih_auto.yar#L1-L129"
		license_url = "N/A"
		logic_hash = "d13e6780f7fe46f9387338ccdb35700eb9e8a8c2ac7c13f232d1064c9386ae55"
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
		$sequence_0 = { 5f ff7508 ff55f4 53 ff15???????? 8bc7 }
		$sequence_1 = { 68???????? e8???????? 8b35???????? 83c40c 50 57 }
		$sequence_2 = { 50 56 e8???????? 59 85c0 59 753c }
		$sequence_3 = { 85c0 59 7507 57 e8???????? 59 e8???????? }
		$sequence_4 = { ff15???????? 56 6880000000 6a03 56 6a01 8d85b8b8ffff }
		$sequence_5 = { 66ab aa 59 33c0 8dbde9faffff 889de8faffff f3ab }
		$sequence_6 = { 3bfe 750a 56 56 56 6a08 }
		$sequence_7 = { e8???????? 6801200000 8d85b8b8ffff 56 50 e8???????? }
		$sequence_8 = { 50 8d854cf6ffff 50 e8???????? 83c430 8d459c 50 }
		$sequence_9 = { 0fafca 0fb65002 03ca 890d???????? 0fb64803 69c960ea0000 }

	condition:
		7 of them and filesize <57344
}