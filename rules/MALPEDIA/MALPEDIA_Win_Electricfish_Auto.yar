rule MALPEDIA_Win_Electricfish_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "b2332381-c1cc-58e9-8fab-7070fccf8e24"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.electricfish"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.electricfish_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "1f7cb8b65f3bb65395bc124290e1a31ce340990c85196e747881fa433bd41f37"
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
		$sequence_0 = { e8???????? 83c404 85c0 0f84e3fdffff 8b442410 6a00 50 }
		$sequence_1 = { e8???????? 8bd8 83c404 85db 7523 683e010000 68???????? }
		$sequence_2 = { c3 8b5104 57 6a77 68???????? 8910 8b39 }
		$sequence_3 = { 8b442408 6855090000 68???????? 6a41 6896010000 6a14 c70050000000 }
		$sequence_4 = { e8???????? 83c418 85c0 0f8fd7faffff 5f 5e 5d }
		$sequence_5 = { 8945c4 8945c8 8945cc 8945d0 89a540ffffff 6aff 894110 }
		$sequence_6 = { 689b010000 68???????? 6a08 e8???????? 83c40c 85c0 751f }
		$sequence_7 = { 51 55 e8???????? 83c408 3bc3 7504 6a6e }
		$sequence_8 = { c3 57 56 e8???????? 83c408 6893000000 68???????? }
		$sequence_9 = { 0fb74550 c7459418001800 c7459848000000 84db 7402 03c0 0fb74d18 }

	condition:
		7 of them and filesize <3162112
}