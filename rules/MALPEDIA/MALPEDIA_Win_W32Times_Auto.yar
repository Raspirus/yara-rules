rule MALPEDIA_Win_W32Times_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "0bfdc72d-d05e-5c1b-8705-7d1b1a1a85f1"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.w32times"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.w32times_auto.yar#L1-L125"
		license_url = "N/A"
		logic_hash = "09784a57b734a06db72c3b3952721b8e38cad13da9a478a5c4cffbebd654009b"
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
		$sequence_0 = { e8???????? 85c0 0f8487030000 6a01 68???????? }
		$sequence_1 = { 83e103 f3a4 8b35???????? 8d8c24f0020000 68???????? 51 ffd6 }
		$sequence_2 = { 83c408 68???????? ff15???????? 85c0 0f85c6060000 ff15???????? }
		$sequence_3 = { ff15???????? 68???????? ff15???????? 396c2418 7410 6a01 }
		$sequence_4 = { 3b9c24000d0000 0f84cc090000 8a8424f0020000 84c0 0f84bd090000 8a8424e8000000 84c0 }
		$sequence_5 = { 8bfd 83c9ff 33c0 8d9424ec010000 f2ae f7d1 2bf9 }
		$sequence_6 = { 8b15???????? 52 ffd3 892d???????? a1???????? 3bc5 7416 }
		$sequence_7 = { f3a5 8bcd 8d9424f4030000 83e103 f3a4 8dbc24f4040000 }
		$sequence_8 = { 683f000f00 6a00 56 ff15???????? 8bf8 }
		$sequence_9 = { 83c40c 85c0 0f85e00c0000 8b4b04 6a04 }

	condition:
		7 of them and filesize <122880
}