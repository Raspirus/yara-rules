rule MALPEDIA_Win_Joao_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "d37cc5ea-3d73-5336-a732-17564803dcb9"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.joao"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.joao_auto.yar#L1-L121"
		license_url = "N/A"
		logic_hash = "86dd7ba6af2ece0f6d3df07328920c1e2520bb8d3e325d921ed8a0a42914959d"
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
		$sequence_0 = { 8bce 897dfc e8???????? 837de810 c745fcffffffff 720c 8b45d4 }
		$sequence_1 = { 8b4e08 2b0e c1f905 3bc8 }
		$sequence_2 = { 8d4dd0 51 8bce 897dfc e8???????? }
		$sequence_3 = { 50 6a0f 68???????? e8???????? 8b5510 8d8df8feffff }
		$sequence_4 = { 8b4804 8b4c3138 c645ef01 4b }
		$sequence_5 = { 8d45f8 50 8bce c745f809000000 897dfc e8???????? 8d4df8 }
		$sequence_6 = { e8???????? 8b4604 83e7e0 033e }
		$sequence_7 = { 8b4c3224 8b443220 c645fc03 85c9 7c15 7f04 }
		$sequence_8 = { 8d4dd4 e8???????? 8d4dd0 51 8bce 897dfc e8???????? }
		$sequence_9 = { 8b4e08 2b0e c1f905 3bc8 736a 8d7e0c 50 }

	condition:
		7 of them and filesize <2867200
}