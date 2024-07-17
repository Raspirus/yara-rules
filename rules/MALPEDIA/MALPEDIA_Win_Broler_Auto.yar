
rule MALPEDIA_Win_Broler_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "5abffeef-f83b-5c44-9f6f-38ecebdd4974"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.broler"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.broler_auto.yar#L1-L124"
		license_url = "N/A"
		logic_hash = "a9e85383ead8a369d8ed21ea68b384350908e471fda84214a900f85e6e6d4412"
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
		$sequence_0 = { 6a00 68???????? 50 68???????? 56 ff15???????? 898520dffcff }
		$sequence_1 = { 39b820b54100 0f8491000000 ff45e4 83c030 3df0000000 72e7 81ffe8fd0000 }
		$sequence_2 = { e8???????? 83c404 33c0 8845f0 8945f1 8945f5 668945f9 }
		$sequence_3 = { 8d8db0dffcff 51 ba???????? e8???????? }
		$sequence_4 = { e8???????? 83c404 33ff be0f000000 89b588fdffff 89bd84fdffff c68574fdffff00 }
		$sequence_5 = { 33ff 3bcf 7564 c743140f000000 897b10 b8???????? }
		$sequence_6 = { 898ed4030000 8b5004 8996d8030000 8b4808 }
		$sequence_7 = { 899d50fdffff ff15???????? 8b9550fdffff 52 8d45a8 68???????? 50 }
		$sequence_8 = { e8???????? e9???????? 50 8d459c 50 }
		$sequence_9 = { 895910 c741140f000000 8d5508 89a51cdffcff 8819 52 }

	condition:
		7 of them and filesize <275456
}