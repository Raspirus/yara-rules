
rule MALPEDIA_Win_Cur1_Downloader_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "2c8bb8d3-c4a4-59f1-99cf-04925e102b6b"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cur1_downloader"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.cur1_downloader_auto.yar#L1-L130"
		license_url = "N/A"
		logic_hash = "b5443d6c58a9050bf16869865e319c3a21a1ce3b38679342db8dce71a1fd94bc"
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
		$sequence_0 = { e8???????? ebd1 488d542440 488b4c2470 e8???????? 8b442438 83c801 }
		$sequence_1 = { 8b442440 ffc0 89442440 8b05???????? 39442440 0f83e4000000 8b442440 }
		$sequence_2 = { c68424e70200006f c68424e80200006e c68424e902000057 c68424ea02000000 }
		$sequence_3 = { 7578 48630d847affff 488d15417affff 4803ca 813950450000 755f b80b020000 }
		$sequence_4 = { c68424b803000069 c68424b90300006e c68424ba03000067 c68424bb0300006c c68424bc03000065 c68424bd0300004f }
		$sequence_5 = { c684248803000065 c684248903000049 c684248a0300006e c684248b03000066 c684248c0300006f c684248d03000072 c684248e0300006d }
		$sequence_6 = { 48c744247000000000 41b918000000 4c8d8424a0000000 488b942488000000 488b8c2490000000 ff15???????? 85c0 }
		$sequence_7 = { 4863442450 0fb78444d0000000 83f85c 750d 8b442450 898424a4000000 eb02 }
		$sequence_8 = { 7d0c 4863442428 c644042400 ebe3 c744242800000000 eb0a 8b442428 }
		$sequence_9 = { c644244933 c644244a37 c644244b62 c644244c34 c644244d37 c644244e39 c644244f32 }

	condition:
		7 of them and filesize <402432
}