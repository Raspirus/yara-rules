
rule MALPEDIA_Win_Lodeinfo_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "47c099ff-69db-5812-85ce-57e24072ce38"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lodeinfo"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.lodeinfo_auto.yar#L1-L129"
		license_url = "N/A"
		logic_hash = "e6a58ad7e2bc0ff5d6e63ebfb8b716b1912a0a95e296af817067906fecf4c3bd"
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
		$sequence_0 = { 894de0 8955f0 8955f8 8955f4 85ff 740a 381433 }
		$sequence_1 = { 85c0 7412 ff75f4 8b55f0 8bc8 e8???????? 83c404 }
		$sequence_2 = { 85ff 742e 8b4c2444 8bc7 }
		$sequence_3 = { 660fefc8 0f114c0620 0f10440630 0f28ca 660fefc8 0f114c0630 83c040 }
		$sequence_4 = { 5d c3 8b75fc 8b55f0 33c9 85d2 7429 }
		$sequence_5 = { 8bda 8b5508 57 8bf9 895df8 8b06 }
		$sequence_6 = { e8???????? 83c404 894708 85c0 750d 39460c 7408 }
		$sequence_7 = { 03c8 8b4510 d1e9 024fff 884c17ff 8b4dd4 3bf3 }
		$sequence_8 = { eb72 8b45f0 8975f4 c64406ff00 eb65 8b45f8 8d7e01 }
		$sequence_9 = { 85c0 748e 33c0 0f57c0 b920010000 8bfa }

	condition:
		7 of them and filesize <712704
}