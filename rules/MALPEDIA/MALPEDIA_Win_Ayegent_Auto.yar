rule MALPEDIA_Win_Ayegent_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "38c6d34b-791e-51ab-b755-5bf91f226c75"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ayegent"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.ayegent_auto.yar#L1-L118"
		license_url = "N/A"
		logic_hash = "7245e65e015426e49adecdb4c2a9413e067a055fe3d65973ee2cacb00da6dd3e"
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
		$sequence_0 = { 80a0609d400000 40 41 41 3bc6 }
		$sequence_1 = { 8d442448 53 50 68???????? 53 }
		$sequence_2 = { 68???????? ffd6 8bf8 33f6 3bfb 897c241c 0f8cf9000000 }
		$sequence_3 = { ff15???????? 8b4c2428 8b542424 51 8b4c2424 52 }
		$sequence_4 = { 8d542440 51 52 ff15???????? 85c0 0f8415030000 8b3d???????? }
		$sequence_5 = { 52 50 ffd6 6a00 8d8c2414010000 }
		$sequence_6 = { 83c408 aa 8d842450040000 6804010000 }
		$sequence_7 = { 55 56 8bb42438050000 33db }
		$sequence_8 = { 72f1 56 8bf1 c1e603 3b9668774000 0f851c010000 }
		$sequence_9 = { 53 51 68???????? ffd6 85c0 }

	condition:
		7 of them and filesize <90112
}