rule MALPEDIA_Win_Tiop_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a48d1e15-9fc1-5bab-9fa2-c3c7b063ec8e"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tiop"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.tiop_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "62d0ea75fcf8689409f77f7c307d37bf3637d8a3da71cff9b0be16f18afd1eb3"
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
		$sequence_0 = { 81ec08010000 55 56 57 b940000000 33c0 8d7c2411 }
		$sequence_1 = { ff15???????? 50 ff15???????? 8b3d???????? 8bf0 ffd7 50 }
		$sequence_2 = { 57 33ed b94f000000 33c0 8d7c240c 896c2408 892d???????? }
		$sequence_3 = { ff15???????? 50 8b44241c 53 50 ff5510 8b4c241c }
		$sequence_4 = { 8b7c2410 56 8b35???????? 894704 ffd6 55 ffd6 }
		$sequence_5 = { f3a4 8b442414 8b7500 8b4c2410 2bf0 03d0 897500 }
		$sequence_6 = { eb2e 50 ffd3 8d7c0002 8bc7 83c003 24fc }
		$sequence_7 = { 6a01 6a00 ffd7 8b1d???????? 8bf0 56 89742410 }
		$sequence_8 = { 83c9ff 33c0 83c404 f2ae f7d1 6a10 49 }
		$sequence_9 = { 8b542418 8b4c2420 8b3d???????? 8944240c 8b44242c 89542408 8b542424 }

	condition:
		7 of them and filesize <712704
}