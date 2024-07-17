rule MALPEDIA_Win_Yakuza_Ransomware_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "11a15f28-8d6d-50f2-ab84-992f1017bc03"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yakuza_ransomware"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.yakuza_ransomware_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "f6b4887f1e5f8fb585f51d15a1308ea3aa15725a1e02d02f26222a8f601e98de"
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
		$sequence_0 = { 8bd1 d1ea b8ffffff1f 2bc2 3bc8 7607 8bc3 }
		$sequence_1 = { e8???????? 3b780c 730e 8b4008 8b34b8 85f6 0f85d7000000 }
		$sequence_2 = { d1f8 837e1408 7202 8b36 50 ff7508 8bce }
		$sequence_3 = { 6a01 6a01 57 8d4d80 e8???????? 8b4580 8d4d80 }
		$sequence_4 = { 8d7018 83c030 8b11 03c7 50 03f7 56 }
		$sequence_5 = { c745fcffffffff 56 8b4de0 41 51 53 8bcf }
		$sequence_6 = { 8b4f14 8b5614 85c9 743e 85c0 750d e8???????? }
		$sequence_7 = { eb17 0fb74644 8d4e24 50 e8???????? 6a2d 8d4e24 }
		$sequence_8 = { 8b06 6a02 51 53 8d8d50ffffff 51 8bce }
		$sequence_9 = { c745f000000000 c7461000000000 c7461407000000 668906 8945fc 8bc3 c745f001000000 }

	condition:
		7 of them and filesize <2811904
}