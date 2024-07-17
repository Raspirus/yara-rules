rule MALPEDIA_Win_Rofin_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "1b07367d-380d-5a5b-bc33-dfe76ecfb58c"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rofin"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.rofin_auto.yar#L1-L128"
		license_url = "N/A"
		logic_hash = "8597563e9ea27355f4e9d99fcf2f4a72dc9ad41d82ef13adb90824429264b4c0"
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
		$sequence_0 = { 014df0 3b06 72b5 eb1a 8b45fc 69c01c010000 03c6 }
		$sequence_1 = { 84c0 c706???????? 7417 8b4604 85c0 7410 }
		$sequence_2 = { 8d442434 53 50 33d2 668b95d0030000 56 8d4c242c }
		$sequence_3 = { c644244163 88542442 c644244528 885c2446 c64424473e c644244800 }
		$sequence_4 = { 8b44240c 8b542404 83ec10 8d4c2400 53 50 }
		$sequence_5 = { 83c408 3bf3 7420 8b4c2420 56 8b513c 52 }
		$sequence_6 = { 72b5 eb1a 8b45fc 69c01c010000 03c6 81781000d00000 7506 }
		$sequence_7 = { f3a4 8d4c246a 6800040000 51 6a00 ff15???????? }
		$sequence_8 = { e8???????? eb73 bf???????? 83c9ff 33c0 f2ae f7d1 }
		$sequence_9 = { 8b45fc 83481c10 8b45fc 89585c 8d45f4 }

	condition:
		7 of them and filesize <409600
}