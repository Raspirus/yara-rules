rule MALPEDIA_Win_Redpepper_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "6d36eb39-39c8-5443-a77b-2290277533bd"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redpepper"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.redpepper_auto.yar#L1-L116"
		license_url = "N/A"
		logic_hash = "e4e4c0e91e25e59e6fb978e405ca0275203329718b6dc395151e5d470e453248"
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
		$sequence_0 = { 57 8bf9 8b870c1e0000 85c0 }
		$sequence_1 = { 8b500c 41 83f904 8b12 8a540aff }
		$sequence_2 = { 8b4d10 881e 50 8901 e8???????? 59 }
		$sequence_3 = { 8b4520 3bc7 7439 68a1000000 68???????? 50 e8???????? }
		$sequence_4 = { 53 55 56 33f6 57 8b7c2428 }
		$sequence_5 = { 752d 689f000000 68???????? 6a26 }
		$sequence_6 = { c3 8b7c2418 85ff 7432 e8???????? }
		$sequence_7 = { 8845f3 8845f4 8845f7 8845f8 }
		$sequence_8 = { 8b742414 6a0f f7d1 49 56 8be9 e8???????? }
		$sequence_9 = { e8???????? 8b44241c 8b6c2428 8b4c2418 }

	condition:
		7 of them and filesize <2482176
}