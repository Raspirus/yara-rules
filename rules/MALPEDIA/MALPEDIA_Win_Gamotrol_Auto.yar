
rule MALPEDIA_Win_Gamotrol_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a4423f00-4d12-5905-ae9f-2ac00b302637"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gamotrol"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.gamotrol_auto.yar#L1-L128"
		license_url = "N/A"
		logic_hash = "dbb5086714c8814bb752b80e0051cf0358b1814ba2516480704e9248f4a5718d"
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
		$sequence_0 = { 5e c3 6a04 b8???????? e8???????? e8???????? 50 }
		$sequence_1 = { ff15???????? 8b4b54 6a04 6800100000 51 56 }
		$sequence_2 = { 90 8bec 85f6 41 49 6843700000 83c40a }
		$sequence_3 = { 6aff 68???????? 68???????? 6a00 ff15???????? 6a00 53 }
		$sequence_4 = { 8be5 90 5d 6803010000 }
		$sequence_5 = { 8d9540fbffff 52 68???????? ffd6 33c0 8945ad 8945b1 }
		$sequence_6 = { c6854fffffff61 c68550ffffff67 889d51ffffff c68552ffffff56 c68553ffffff69 889d54ffffff }
		$sequence_7 = { 0fbec2 0fb680a0ed2e00 83e00f 8b4db8 6bc009 0fb68408c0ed2e00 6a08 }
		$sequence_8 = { 8b01 57 ff5004 5f 5e c3 8b442404 }
		$sequence_9 = { 49 41 49 90 8be5 90 }

	condition:
		7 of them and filesize <376832
}