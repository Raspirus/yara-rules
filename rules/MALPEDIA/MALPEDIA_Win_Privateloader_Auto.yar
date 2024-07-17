rule MALPEDIA_Win_Privateloader_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "704976b4-103d-5caa-b3a7-f03a44637bd7"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.privateloader"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.privateloader_auto.yar#L1-L183"
		license_url = "N/A"
		logic_hash = "15e13900aae7d6be3cc889a3774b293d4c50bba5cbabc1926697368cc70d28fc"
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
		$sequence_0 = { 8965ec 8b55ec 8955e8 8d45f8 }
		$sequence_1 = { 894df4 8b55fc 837a1410 7209 }
		$sequence_2 = { 0fb64dec 85c9 7408 8b55fc 8b02 8945e8 }
		$sequence_3 = { 8b4dec 8b5508 895110 8b4508 8945e4 8b4de8 034de4 }
		$sequence_4 = { 8b45d8 8b4ddc 8b55d0 8b75d4 }
		$sequence_5 = { 8b4dec e8???????? 8b4df0 e8???????? 8845fc }
		$sequence_6 = { 8975d4 8b45d0 8b55d4 5e }
		$sequence_7 = { 8b4de8 8b75ec 2bc8 1bf2 894de0 8975e4 a1???????? }
		$sequence_8 = { e8???????? 33d2 b93f000000 f7f1 }
		$sequence_9 = { 8b4590 8b4d94 8b5588 8b758c }
		$sequence_10 = { a3???????? 33c0 5e c3 3b0d???????? }
		$sequence_11 = { 896c2404 8bec 81ec68010000 a1???????? 33c5 8945fc 56 }
		$sequence_12 = { d81d???????? c9 b8ffffffff 99 c3 56 8b35???????? }
		$sequence_13 = { 13f1 83c201 8955e0 83d600 }
		$sequence_14 = { 6a04 8d4310 50 6a06 }
		$sequence_15 = { 7507 6800008000 eb02 6a00 }
		$sequence_16 = { 8b45e4 50 51 52 }
		$sequence_17 = { 0bc8 56 57 7529 }
		$sequence_18 = { 03d0 8b4d9c 13f1 83c201 }

	condition:
		7 of them and filesize <3670016
}