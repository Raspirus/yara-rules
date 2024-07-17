rule MALPEDIA_Win_Necurs_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "3d1b7316-0e79-5ade-97ef-8f3ac3ffb54d"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.necurs"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.necurs_auto.yar#L1-L159"
		license_url = "N/A"
		logic_hash = "75c1414f6695a00e2fea038874de3164067ad0287567965dcfd36d5ca522d078"
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
		$sequence_0 = { 13f2 a3???????? 8935???????? 890d???????? 8bc1 5e }
		$sequence_1 = { 030d???????? a3???????? a1???????? 13f2 a3???????? }
		$sequence_2 = { 13f2 33d2 030d???????? a3???????? }
		$sequence_3 = { 8bc2 034508 5e 5d c3 55 }
		$sequence_4 = { 03c8 a1???????? 13f2 33d2 }
		$sequence_5 = { 56 8bf2 ba06e0a636 f7e2 }
		$sequence_6 = { 397508 7604 33c0 eb12 }
		$sequence_7 = { 2b7508 33d2 46 f7f6 8bc2 034508 }
		$sequence_8 = { 8d85ecfbffff 57 50 e8???????? 83c410 }
		$sequence_9 = { 33d7 33c1 52 50 }
		$sequence_10 = { 6a7d 50 ffd6 59 }
		$sequence_11 = { 8bc1 0bc7 7409 8bc1 8bd7 e9???????? }
		$sequence_12 = { 57 57 8d8574ffffff 50 }
		$sequence_13 = { 6a7b 50 ffd6 8bf8 59 59 }
		$sequence_14 = { 53 ff15???????? 59 33c0 5e }
		$sequence_15 = { a1???????? 33d2 f7f1 ff05???????? }

	condition:
		7 of them and filesize <475136
}