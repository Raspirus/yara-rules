rule MALPEDIA_Win_Open_Carrot_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a3d97757-e9bd-5b96-a3d4-9f325722b76a"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.open_carrot"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.open_carrot_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "bc0e7aafdfe5fe87787ac92bf2b362a8818b18c35ce921dfe615312cba0c80f1"
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
		$sequence_0 = { b910000000 e8???????? 4889442430 c700ffffffff 48c74008ffffffff 8b4c2438 8908 }
		$sequence_1 = { b9c8dcfb75 ffc1 c1e106 83e9ff 83c101 6807ab8f5e 4c893424 }
		$sequence_2 = { ffd0 eb05 bd01000000 440fb6e5 443bed 7c7a 488b15???????? }
		$sequence_3 = { 8bc3 e9???????? 41b805000000 488d153c9a1800 488bcf e8???????? 85c0 }
		$sequence_4 = { ffcf 488d9512070000 4903d4 4c63c7 664289b445100f0000 e8???????? 6639b510170000 }
		$sequence_5 = { 4881cb3f000000 48c7c000020000 4981c46f000000 4809f0 4d0fb72424 4881c204000000 4809c6 }
		$sequence_6 = { 83fe07 7772 4c8d0dad8df9ff 4863c6 418b8481f0750600 4903c1 ffe0 }
		$sequence_7 = { e9???????? 488d05de191400 894c2420 4c8d2dabb30f00 89742424 eb42 488d05aeb30f00 }
		$sequence_8 = { 4c8d0d91850b00 8d4a98 448d42ef e8???????? e9???????? 4c8b4310 488bd7 }
		$sequence_9 = { 7422 41b8a3000000 488d15c7ff0900 e8???????? 48898380000000 4885c0 0f842f010000 }

	condition:
		7 of them and filesize <8377344
}