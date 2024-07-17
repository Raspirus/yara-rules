rule MALPEDIA_Win_Cmstar_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "aaad9b46-b601-594d-9a0b-7ba351f67235"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cmstar"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.cmstar_auto.yar#L1-L174"
		license_url = "N/A"
		logic_hash = "c5a1f8b6b909717cbba254781a42955dfe756a8fae37e256ff72ffa4cd43d897"
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
		$sequence_0 = { 836dfc10 ff75fc 8945e0 8b45dc 83c310 }
		$sequence_1 = { 8b4dec c1e802 6a04 52 8d0481 50 e8???????? }
		$sequence_2 = { ff75e0 ff30 e8???????? 8b4df8 }
		$sequence_3 = { ff15???????? 8bc6 e9???????? 6a10 8d45d0 53 }
		$sequence_4 = { ff15???????? 6a04 e8???????? be00040000 }
		$sequence_5 = { 56 bb04010000 57 53 }
		$sequence_6 = { ff15???????? 6a03 58 5f 5e 5b c9 }
		$sequence_7 = { 85c0 7504 6a03 eb0d 803b4d }
		$sequence_8 = { 81ce00ffffff 46 8a1c06 88542418 881c01 8b5c2418 }
		$sequence_9 = { 8b2d???????? 8b44241c 8bc8 48 85c9 8944241c 7e65 }
		$sequence_10 = { 5d 741c 8a41ff 3ac3 740b 3cff }
		$sequence_11 = { 7505 a1???????? 50 ff15???????? eb17 }
		$sequence_12 = { 8bf0 8d5601 52 e8???????? 83c404 8bf8 8d442414 }
		$sequence_13 = { e9???????? 55 83f801 57 7532 }
		$sequence_14 = { 50 ff15???????? 83f8ff 89442420 7507 33f6 e9???????? }
		$sequence_15 = { 8b5c2408 55 8b6c2414 56 57 8b7c2418 8bcb }

	condition:
		7 of them and filesize <4268032
}