
rule MALPEDIA_Win_Ice_Ix_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "f7014fa0-a713-5faf-ab08-c5718709e2e0"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ice_ix"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.ice_ix_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "fab5667b12ec8f3fc934ce2ccdb85e5f1acf73115ae434c2a20cd983e8b43fbd"
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
		$sequence_0 = { 3bc3 748c 6a01 8d4584 50 6883346425 e8???????? }
		$sequence_1 = { 85db 0f844b020000 81fe00020000 0f873f020000 83fe06 0f86e5000000 8b03 }
		$sequence_2 = { 50 e8???????? 50 53 8d857cfeffff 50 e8???????? }
		$sequence_3 = { 56 57 6a02 5b 53 6821634578 }
		$sequence_4 = { 8d75b8 b891000000 e8???????? 8d75d0 b892000000 e8???????? 8d75dc }
		$sequence_5 = { 0f84dc000000 8d442420 50 ff15???????? 8db424c0000000 b8a2000000 e8???????? }
		$sequence_6 = { 6a73 8d74243c 58 e8???????? 8bc6 89442410 }
		$sequence_7 = { 6a42 8db550ffffff 58 e8???????? 8b75f4 8b55f0 3bf7 }
		$sequence_8 = { 0f84a7000000 83f8ff 0f849e000000 6a3b 8d75e0 58 897dec }
		$sequence_9 = { 68cc000000 6a2d 58 e8???????? ff75d0 ff15???????? 5f }

	condition:
		7 of them and filesize <327680
}