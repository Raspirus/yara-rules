rule MALPEDIA_Win_Taintedscribe_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "62c390fd-70d7-5d2c-ab35-2685bb241f72"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.taintedscribe"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.taintedscribe_auto.yar#L1-L116"
		license_url = "N/A"
		logic_hash = "9db61e016991abab1a5db24c238ca36eb7d715a36997cda629b6ade68b20e5c3"
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
		$sequence_0 = { 8bc8 8b858cf7ffff 83e103 6a02 f3a4 6a00 }
		$sequence_1 = { 8d4ddc 898db8fcffff 8bcf 0facd108 }
		$sequence_2 = { 8b5358 898d88fbffff 8b4b50 0f94c0 }
		$sequence_3 = { 85c0 7405 8b4d98 8908 85db }
		$sequence_4 = { 894e3c 894e44 895648 33c0 5e 8b4dfc 33cd }
		$sequence_5 = { 8b4dcc 894308 8b45d0 50 }
		$sequence_6 = { 42 83fa1c 7cbb 81ff00010000 0f94c1 0fb6c1 68???????? }
		$sequence_7 = { c68577fbffff01 7507 c68577fbffff00 c78570fbffff08000000 }
		$sequence_8 = { 83c40c 098658af0100 8d0419 89865caf0100 83f810 }
		$sequence_9 = { bb01000000 d3e3 33c0 85db 7e1e 8d4900 }

	condition:
		7 of them and filesize <524288
}