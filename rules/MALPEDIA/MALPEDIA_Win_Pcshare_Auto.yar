
rule MALPEDIA_Win_Pcshare_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "7acb8456-1058-55a0-81ba-27e3cb590933"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pcshare"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.pcshare_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "7ae15dd51d8c67d0995dcb010803cd76a95f2636c119f9eefe8dfedf04aaf2b7"
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
		$sequence_0 = { 8b48fc 03f7 8b78f8 8bd1 03fb c1e902 }
		$sequence_1 = { 33ed 8d0c18 8bc3 99 }
		$sequence_2 = { e8???????? 85c0 59 743e 8305????????20 8d0c9da0720610 }
		$sequence_3 = { 8bc6 8b0c8da0720610 8d04c0 80648104fd 8d448104 8bc7 5f }
		$sequence_4 = { 8d4c2418 50 51 e8???????? 83c40c 84c0 7439 }
		$sequence_5 = { c1e705 f6441f0e01 7428 8b4c2474 81e2ffff2f00 895008 8b542440 }
		$sequence_6 = { 51 eb07 8b16 8d441a02 }
		$sequence_7 = { 85c0 7505 b8???????? 8078fffe 732f }
		$sequence_8 = { 83c418 894c2424 b940000000 f3ab 66ab aa b940000000 }
		$sequence_9 = { 3bd0 0f8c93fdffff 33ed 5b 8b74243c 8a4c241c }

	condition:
		7 of them and filesize <893708
}