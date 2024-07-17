rule MALPEDIA_Win_Silon_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "74e356eb-e3ab-55df-a58b-86af4144d8aa"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.silon"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.silon_auto.yar#L1-L129"
		license_url = "N/A"
		logic_hash = "e4ecb086584bedec65219eab1069013db28049e75ec56b31d70ca83f4cf849d8"
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
		$sequence_0 = { 83ec18 c745f000000000 c745f400000000 c745f800000000 33c0 8945fc }
		$sequence_1 = { 83c408 8945f4 837df400 7507 33c0 e9???????? c745f800000000 }
		$sequence_2 = { 81ec3c020000 c785c4fdffff00000000 c745fc00000000 c745f800000000 837d0800 }
		$sequence_3 = { 0fbe11 83fa61 7c20 8b4508 0345fc 0fbe08 83f97a }
		$sequence_4 = { 8b4d0c 8b55f8 895104 8b45f4 50 e8???????? 83c404 }
		$sequence_5 = { 6a00 8d8df4feffff 51 8d95f8feffff 52 6a01 8b4508 }
		$sequence_6 = { 50 e8???????? 83c408 eb61 8b4d08 }
		$sequence_7 = { e8???????? 83c404 8b55fc 52 e8???????? 83c404 8945ec }
		$sequence_8 = { 8b5508 8955e8 837de800 7507 33c0 e9???????? 8b45e8 }
		$sequence_9 = { 5d c20c00 ff25???????? 60 33c9 8b742424 33c0 }

	condition:
		7 of them and filesize <122880
}