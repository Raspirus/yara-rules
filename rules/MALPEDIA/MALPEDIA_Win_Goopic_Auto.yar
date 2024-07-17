rule MALPEDIA_Win_Goopic_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "af6daaef-2e7b-547b-a95b-f4526c03929f"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.goopic"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.goopic_auto.yar#L1-L125"
		license_url = "N/A"
		logic_hash = "09cf2d520274006f21b8dfb7e13c7364d612efefae1767684cd3f4a4dac575b5"
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
		$sequence_0 = { 8d85fcf7ffff 50 ff15???????? 6a00 6a00 6a00 6a00 }
		$sequence_1 = { 57 ff742428 ff15???????? 85c0 740d }
		$sequence_2 = { c785d0fdffff2c020000 ff15???????? 8bf0 8d85d0fdffff 50 56 }
		$sequence_3 = { 50 8b08 ff11 8b442414 50 }
		$sequence_4 = { ff15???????? 8bd7 8d8df8bfffff e8???????? 57 68???????? ff15???????? }
		$sequence_5 = { 8bfa ffd6 8bd8 895dfc }
		$sequence_6 = { 50 6aff 68???????? 6a00 6a00 ffd7 8d842448190000 }
		$sequence_7 = { 0f8664ffffff 8b4dfc 33c0 5f 5e 33cd 5b }
		$sequence_8 = { 53 ff15???????? 8bf8 85ff 0f84f4000000 56 6a00 }
		$sequence_9 = { c785c0fdffff305d4000 eb0a c785c0fdffff245d4000 8d85b4fdffff c785c4fdffff3c5d4000 50 }

	condition:
		7 of them and filesize <114688
}