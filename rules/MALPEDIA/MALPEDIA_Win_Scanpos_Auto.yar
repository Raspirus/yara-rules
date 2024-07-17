rule MALPEDIA_Win_Scanpos_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "8293fa8e-4228-517c-a26a-04301bca2110"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.scanpos"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.scanpos_auto.yar#L1-L120"
		license_url = "N/A"
		logic_hash = "b005df89a44c0f26903a8ba8f3d418d77b4a13957700f79b1d7571fcff516771"
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
		$sequence_0 = { c645b800 e8???????? c645fc01 837de810 8b45d4 }
		$sequence_1 = { c745d830124100 e8???????? 8b4508 8b4dec 8945e4 40 }
		$sequence_2 = { 52 57 8bfe 8d75d4 e8???????? be10000000 c645fc00 }
		$sequence_3 = { 80f939 0f8fd3010000 80f930 0f8cca010000 0fbec0 0fbec9 8d848010ffffff }
		$sequence_4 = { 7f04 3bcb 7611 8945d8 }
		$sequence_5 = { 8b4dac c745cc0f000000 c745c800000000 c645b800 e8???????? c645fc01 }
		$sequence_6 = { 50 8d4d80 e8???????? 83c40c 57 }
		$sequence_7 = { 84db 7507 6a01 e8???????? 8d8de8feffff }
		$sequence_8 = { 57 8d8dcbfeffff 51 6804010000 }
		$sequence_9 = { 2bc1 8bcf 03c3 83cfff 2bf8 3bf9 730a }

	condition:
		7 of them and filesize <229376
}