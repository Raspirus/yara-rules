
rule MALPEDIA_Win_Usbferry_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "62065071-13fe-542b-a291-fb80bd43202d"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.usbferry"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.usbferry_auto.yar#L1-L169"
		license_url = "N/A"
		logic_hash = "886d5513793c468df6b8e0477647a179848882846be144ad6058e6cfbd13a26d"
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
		$sequence_0 = { 52 8b45e0 50 ff15???????? 85c0 742c }
		$sequence_1 = { 8b9598f5ffff 2b9588f5ffff 8b8588f5ffff 89857cf5ffff 899578f5ffff }
		$sequence_2 = { e9???????? ff75e0 a1???????? ff5060 8d45e0 }
		$sequence_3 = { c3 3b0d???????? f27502 f2c3 f2e960030000 55 }
		$sequence_4 = { 8b525c e8???????? 8b15???????? 8b4d84 ff7210 89425c }
		$sequence_5 = { 803f2e 7402 33ff 85ff 7407 8d45e9 }
		$sequence_6 = { c645df6f c645e06e c645e100 c685a4f5ffff00 68ff030000 }
		$sequence_7 = { 2b858cf5ffff 8b8d8cf5ffff 898d84f5ffff 898580f5ffff 8d95a8feffff 83c2ff }
		$sequence_8 = { 8b7d0c 33db 895ddc c745e000040000 895dfc 8d45dc }
		$sequence_9 = { 89814c010000 8b09 e8???????? 8b0d???????? ff7110 8b9154010000 }
		$sequence_10 = { ff7110 8b517c 894178 8b09 e8???????? 8b0d???????? }
		$sequence_11 = { 8a460e 8bcf 8845fb 8d45fb }
		$sequence_12 = { 33c5 8945fc c685fcfffeff00 68ffff0000 }
		$sequence_13 = { 8885a0f5ffff 838590f5ffff01 80bda0f5ffff00 75e1 }
		$sequence_14 = { 0f2805???????? 0f1145c8 6a00 0f2805???????? 0f1145d8 50 }
		$sequence_15 = { 50 8d45f0 64a300000000 c745e000000000 c745fc00000000 837d2000 }

	condition:
		7 of them and filesize <638976
}