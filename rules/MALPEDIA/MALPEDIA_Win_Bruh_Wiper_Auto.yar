
rule MALPEDIA_Win_Bruh_Wiper_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "8004678f-c7f1-56db-b368-30e9334ba4b0"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bruh_wiper"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.bruh_wiper_auto.yar#L1-L119"
		license_url = "N/A"
		logic_hash = "26b32a2c0d923fc99fb91e4beb18e36e72d9c523fef8bdb0bb63ddd5fd11ff5a"
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
		$sequence_0 = { e8???????? 83c40c be01080000 0f1f8000000000 }
		$sequence_1 = { 83ee01 75e3 8b4dfc 5f 5e }
		$sequence_2 = { 8d45f4 57 50 ff15???????? ff15???????? }
		$sequence_3 = { 68b40200c0 ffd6 8b4dfc 5f 33cd 5e }
		$sequence_4 = { 6a00 8d85f8fdffff 50 6800020000 8d85fcfdffff 50 }
		$sequence_5 = { 68???????? 57 ffd3 6800020000 8d85fcfdffff 6a00 }
		$sequence_6 = { 50 ffd6 8bf0 8d45fb 50 6a00 6a01 }
		$sequence_7 = { 6800200000 68???????? 57 ffd3 6800020000 8d85fcfdffff }
		$sequence_8 = { e8???????? 83c40c be01080000 0f1f8000000000 6a00 }
		$sequence_9 = { 50 ffd6 68???????? 68???????? 8bf8 }

	condition:
		7 of them and filesize <65536
}