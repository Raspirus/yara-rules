rule MALPEDIA_Win_Caddywiper_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "24926b93-f761-5ed3-a63e-3417e035ba52"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.caddywiper"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.caddywiper_auto.yar#L1-L116"
		license_url = "N/A"
		logic_hash = "79a75ac7d216323abd7ca177a49671b9ea50088d3b0d895d69cfd4d03ce4d9ea"
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
		$sequence_0 = { 8345b404 66837dac00 75c4 c745a800000000 }
		$sequence_1 = { c68592feffff64 c68593feffff00 c68594feffff76 c68595feffff00 c68596feffff61 c68597feffff00 }
		$sequence_2 = { 51 e8???????? 83c408 8985b0fbffff c785f4f1ffff00000000 c68588fbffff4c }
		$sequence_3 = { e9???????? 6a00 8b95acf1ffff 52 ff9564f7ffff }
		$sequence_4 = { 8b4dfc 8b5508 c7048a00000000 ebd7 }
		$sequence_5 = { c645b900 c645ba39 c645bb00 c645bc00 c645bd00 8d4d98 898df4f7ffff }
		$sequence_6 = { c685a3feffff00 c685a4feffff6c c685a5feffff00 c685a6feffff6c c685a7feffff00 }
		$sequence_7 = { c6459264 c6459300 8d458c 50 8d8d90feffff }
		$sequence_8 = { 8985fcf7ffff 8d55c0 52 8d45dc }
		$sequence_9 = { 7407 8b4598 50 ff55fc 8b4594 8be5 }

	condition:
		7 of them and filesize <33792
}