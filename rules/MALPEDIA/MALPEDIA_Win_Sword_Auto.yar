rule MALPEDIA_Win_Sword_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "48310a96-8b09-5184-8f0c-c81d31bbe550"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sword"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.sword_auto.yar#L1-L120"
		license_url = "N/A"
		logic_hash = "f0b3a1cc57dfaff82b285dd4a0f174f5006c9f22ab9c244578d6f7f68d086b5a"
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
		$sequence_0 = { f7d1 2bf9 8d942484020000 8bf7 8bfa }
		$sequence_1 = { ff15???????? 8b8c2434000100 50 8b84243c000100 8d542424 }
		$sequence_2 = { 50 8d54241c 51 52 ff15???????? 85c0 0f8488090000 }
		$sequence_3 = { 49 885c29ff 807d0022 7520 8d7d01 }
		$sequence_4 = { 83c9ff 33c0 8d942488030000 f2ae f7d1 49 }
		$sequence_5 = { 77c8 bf???????? 83c9ff 33c0 f2ae f7d1 }
		$sequence_6 = { b940000000 33c0 8d7c2419 8894241c010000 f3ab }
		$sequence_7 = { 83c9ff 33c0 f2ae f7d1 2bf9 55 }
		$sequence_8 = { 8dbc2494060000 83c9ff 33c0 f2ae f7d1 49 }
		$sequence_9 = { f7d1 49 83f903 77c8 bf???????? }

	condition:
		7 of them and filesize <106496
}