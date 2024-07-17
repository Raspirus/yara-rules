
rule MALPEDIA_Win_Eternal_Petya_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "bf49aeac-2e4f-5384-8db1-b43fb4139322"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.eternal_petya"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.eternal_petya_auto.yar#L1-L162"
		license_url = "N/A"
		logic_hash = "715ae6ddfaceb7ac967a454caeda07039960e25d99f3dc3f83571a182c2a56de"
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
		$sequence_0 = { 55 8bec 51 57 68000000f0 }
		$sequence_1 = { 53 8d4644 50 53 }
		$sequence_2 = { 57 68000000f0 6a18 33ff }
		$sequence_3 = { 53 6a21 8d460c 50 }
		$sequence_4 = { 68f0000000 6a40 ff15???????? 8bd8 }
		$sequence_5 = { 49 75f2 8b4364 034360 8b4b68 894dd4 }
		$sequence_6 = { 8945d0 8bc7 8b7df8 d3e8 8b4de0 03c1 8d3c87 }
		$sequence_7 = { 55 8bec 8b4d0c baff000000 }
		$sequence_8 = { 8d4508 50 53 ff750c 897508 }
		$sequence_9 = { 68???????? e8???????? 85c0 7403 83ce02 }
		$sequence_10 = { 68e8030000 ff15???????? 3bfe 75d3 }
		$sequence_11 = { 55 8bec 8b5508 53 56 57 8b721c }
		$sequence_12 = { 8b07 85c0 75c3 8b75f4 }
		$sequence_13 = { e8???????? 894610 895614 8bc6 5f 5e }
		$sequence_14 = { 898502fcffff 8b85e8fbffff 99 81e2ff010000 }
		$sequence_15 = { 56 51 ffd3 8b15???????? 56 52 8985f0fbffff }

	condition:
		7 of them and filesize <851968
}