
rule MALPEDIA_Win_Xiaoba_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "9683766b-1f7a-5c2a-bffb-7de9b80367d1"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xiaoba"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.xiaoba_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "52112f4a96abd368fbd89cb5e047b8d530704099fd198766e1597b7a0bbb2ccf"
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
		$sequence_0 = { 58 8945ec e9???????? 8b5dfc 83c320 895dd0 6801030080 }
		$sequence_1 = { b801000000 c20c00 8b9024010000 8b44240c 8910 b801000000 c20c00 }
		$sequence_2 = { 8b5c243c 8b7c2464 8b542428 8b442430 03c3 42 89442430 }
		$sequence_3 = { dc442410 dd5c2410 e9???????? db8740010000 dc6c2418 dd5c2418 e9???????? }
		$sequence_4 = { 8b8894010000 33d2 85c9 0f95c2 8bc2 c20800 8b90b4010000 }
		$sequence_5 = { 8d54b500 8b3c02 8d44f500 83c704 57 50 e8???????? }
		$sequence_6 = { 85c9 7519 8b54240c 33c9 890a 8b8820010000 894a04 }
		$sequence_7 = { 85c0 be???????? 7505 be???????? e8???????? 8b4008 56 }
		$sequence_8 = { 8b10 52 e8???????? 83c404 8b4c2474 8901 8d4c2414 }
		$sequence_9 = { 8903 8965e8 6800000000 6800000000 6800000000 ff75f0 6800000000 }

	condition:
		7 of them and filesize <5177344
}