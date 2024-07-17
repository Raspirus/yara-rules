rule MALPEDIA_Win_Glassrat_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "daeaa019-8217-55aa-beac-5fb62572b79c"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.glassrat"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.glassrat_auto.yar#L1-L117"
		license_url = "N/A"
		logic_hash = "c91259f84ec94eec4bc87c666b3c91ba45af3572c135cc4f200070d560141e5d"
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
		$sequence_0 = { 8d542438 83c9ff 33c0 f2ae f7d1 2bf9 8bc1 }
		$sequence_1 = { ff15???????? 33c0 8b5504 8944241d 8d4c241c }
		$sequence_2 = { 747a 3bfe 7476 56 56 56 53 }
		$sequence_3 = { 895db8 895dbc ff15???????? 85c0 0f84bb000000 }
		$sequence_4 = { 3bc8 b802000000 0f85b4000000 33d2 b909020000 52 83ec10 }
		$sequence_5 = { 6a04 51 52 8844243b }
		$sequence_6 = { 8b460c 53 53 57 50 }
		$sequence_7 = { 8bce ff12 57 ff15???????? 8d4c2420 }
		$sequence_8 = { 89442418 ff15???????? 8b4d04 8b1d???????? }
		$sequence_9 = { 89442408 89542404 8a15???????? 33c0 }

	condition:
		7 of them and filesize <81920
}