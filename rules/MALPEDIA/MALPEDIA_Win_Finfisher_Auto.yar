rule MALPEDIA_Win_Finfisher_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "3ef79a6b-24c3-58ed-a290-c5a2a7e3fb1b"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.finfisher"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.finfisher_auto.yar#L1-L148"
		license_url = "N/A"
		logic_hash = "dcf5252aa492d908a47d122045beaf12bf03e72009d0665a415b9ab4e015a1e5"
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
		$sequence_0 = { 68???????? 6804010000 8d85ccf9ffff 50 }
		$sequence_1 = { 56 8d85ccf9ffff 50 e8???????? }
		$sequence_2 = { 6a20 6a03 8d8594f7ffff 50 8d8578f7ffff 50 68000000c0 }
		$sequence_3 = { 663bc1 7506 8345e404 ebd8 }
		$sequence_4 = { 0f853affffff c785d0fbffffd5d8ffff e9???????? 8b07 83e808 }
		$sequence_5 = { 52 68a0608000 eb11 8b4708 8b4dd4 }
		$sequence_6 = { 397714 7403 56 eb02 6a02 56 50 }
		$sequence_7 = { e8???????? 56 e8???????? 8b861c030000 3d10270000 }
		$sequence_8 = { 56 8d859cf7ffff 50 56 a1???????? }
		$sequence_9 = { 85db 7424 8b17 8d448614 8b08 }
		$sequence_10 = { e9???????? 8b859cf7ffff ff7004 ff15???????? 8985c0f7ffff 8b8d9cf7ffff }
		$sequence_11 = { 6a09 ff15???????? 3bc6 7490 8bd0 }
		$sequence_12 = { ffb5b8f7ffff eb5f 8d8578f7ffff 50 6a01 8d85acf7ffff }
		$sequence_13 = { 8d85acfbffff 50 53 56 }

	condition:
		7 of them and filesize <262144
}