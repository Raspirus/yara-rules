rule MALPEDIA_Win_Aperetif_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "dd57eb34-4374-5f40-adeb-74673af556ba"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.aperetif"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.aperetif_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "cb1f1d595273c378c0af7214424a9c75d431ec33b0d3744330f8349a67692fb4"
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
		$sequence_0 = { 8b4108 8975e4 c70100000000 c7410400000000 8945ec c7410800000000 c645f301 }
		$sequence_1 = { e8???????? 8a45d8 884524 8b0e c645fc02 85c9 0f8412010000 }
		$sequence_2 = { 50 8d45f4 64a300000000 8bd9 895db8 8b7508 837e1000 }
		$sequence_3 = { f20f118424f8080000 8b0cb0 85c9 7422 8b742464 90 0fb7047e }
		$sequence_4 = { ff74242c 57 e8???????? 83c410 eb14 8b8724000800 b900000200 }
		$sequence_5 = { 8954242c 660f1f440000 53 ff742424 68c0000000 56 55 }
		$sequence_6 = { ff742410 ff742424 e8???????? 83c408 897c2410 89742450 8b44245c }
		$sequence_7 = { e8???????? ff742434 53 e8???????? ff742428 53 e8???????? }
		$sequence_8 = { ff5210 8b4dc8 c7451803000000 85c9 7418 8b11 8d45a4 }
		$sequence_9 = { e8???????? c7868400000000000000 8b37 8b8e84000000 85c9 7506 8b8e88000000 }

	condition:
		7 of them and filesize <10500096
}