rule MALPEDIA_Win_Tildeb_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "e4d2b91f-a0b2-5435-bc42-03da5ff53194"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tildeb"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.tildeb_auto.yar#L1-L126"
		license_url = "N/A"
		logic_hash = "5eed583e8de669a9ccc3c14def00c8dc34c80dd8549b8a02a48ebd34aae4a3b5"
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
		$sequence_0 = { 8d4dbc 51 56 ff15???????? 56 ff15???????? }
		$sequence_1 = { 6a00 6a00 ff15???????? 85c0 0f84f5090000 68???????? }
		$sequence_2 = { 57 6a40 c644241300 ff15???????? 50 ff15???????? }
		$sequence_3 = { 85c0 7445 50 68???????? 68???????? ff15???????? 83c40c }
		$sequence_4 = { e8???????? 6a00 6a08 8d85d4f5ffff 50 }
		$sequence_5 = { 68???????? 57 56 ff15???????? 8945bc 85c0 7457 }
		$sequence_6 = { c3 b815000000 5e 81c494010000 c3 f7d8 5e }
		$sequence_7 = { eb40 8d458c 50 68???????? eb35 }
		$sequence_8 = { 53 55 8bac2410010000 56 8b35???????? 57 68???????? }
		$sequence_9 = { 6800000088 68???????? 68???????? 6a00 ff15???????? 8b0d???????? }

	condition:
		7 of them and filesize <8532488
}