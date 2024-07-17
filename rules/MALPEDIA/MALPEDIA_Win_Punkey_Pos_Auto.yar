
rule MALPEDIA_Win_Punkey_Pos_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "846510df-399c-5c73-991a-33d5b6390d78"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.punkey_pos"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.punkey_pos_auto.yar#L1-L121"
		license_url = "N/A"
		logic_hash = "afbb6da5e69098feb647a1b39faf19c917a9fcb87281ef711eecf3479b712e35"
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
		$sequence_0 = { ffd7 a3???????? 85c0 74ae 5f }
		$sequence_1 = { 8bec 837d0c01 56 57 756b }
		$sequence_2 = { 837d0c01 56 57 756b 8b4508 }
		$sequence_3 = { ff15???????? 8bf0 85f6 7508 5f 33c0 5e }
		$sequence_4 = { 33c0 5e 5d c20c00 8b3d???????? }
		$sequence_5 = { 68e7070000 50 ff15???????? ff05???????? 8b0d???????? }
		$sequence_6 = { 55 8bec 8b4508 85c0 7919 8b4d10 8b550c }
		$sequence_7 = { 6a02 a3???????? ff15???????? a3???????? 33c0 }
		$sequence_8 = { 52 50 a1???????? 50 ff15???????? 5d c20c00 }
		$sequence_9 = { 8bf0 85f6 7508 5f 33c0 5e }

	condition:
		7 of them and filesize <499712
}