
rule MALPEDIA_Win_Backswap_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "8b9036c3-1342-5fdd-b202-655dad83c8d1"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.backswap"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.backswap_auto.yar#L1-L125"
		license_url = "N/A"
		logic_hash = "a378488e042d6e06f37e68439e6beddf9b3f11fc0a2449d478058f24368f291d"
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
		$sequence_0 = { 5f 5a 5b c9 c21000 83f0ff 5e }
		$sequence_1 = { 8b7508 ff4508 8bfb 3bd3 0f8572ffffff 33c9 e9???????? }
		$sequence_2 = { 33d2 8bdf 4b eb1c 85c9 }
		$sequence_3 = { eb1c 85c9 7508 3bdf 7404 }
		$sequence_4 = { ebd4 3c3f 74c4 3c2a 7508 8bdf 897508 }
		$sequence_5 = { f366a5 59 5f 5e c9 c20c00 55 }
		$sequence_6 = { 74ed 33c0 eb04 8bc6 }
		$sequence_7 = { 4b eb1c 85c9 7508 3bdf 7404 8bce }
		$sequence_8 = { 83f0ff 5e 5f 5a 5b }
		$sequence_9 = { 7482 8b7508 ff4508 8bfb 3bd3 0f8572ffffff 33c9 }

	condition:
		7 of them and filesize <122880
}