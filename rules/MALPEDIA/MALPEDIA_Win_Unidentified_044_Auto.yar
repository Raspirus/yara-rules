rule MALPEDIA_Win_Unidentified_044_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a037a55a-a1d2-5696-aa65-bcad92ff6480"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_044"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.unidentified_044_auto.yar#L1-L119"
		license_url = "N/A"
		logic_hash = "fa0bbb48e3a00969b6207e7af2c24fceeabe6227dd53aafea6a4369ea97af4c2"
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
		$sequence_0 = { 8bca 8bd8 e8???????? 83c404 84c0 7409 668b542408 }
		$sequence_1 = { 3bcf 7416 8d9b00000000 80792400 7403 }
		$sequence_2 = { c3 8b8424e4020000 6a10 6a00 50 }
		$sequence_3 = { 74b3 33ff 397c2418 76ab 33c0 }
		$sequence_4 = { ff15???????? 3d1e270000 7552 8b442408 85c0 }
		$sequence_5 = { 2bf0 03d8 85f6 7fe2 }
		$sequence_6 = { 803e00 8be8 743f 53 57 }
		$sequence_7 = { ffd5 8bb42464050000 85c0 7f85 7c24 f644242420 0f8468feffff }
		$sequence_8 = { c7460403000000 ffd3 5b 5f 32c0 5e }
		$sequence_9 = { 55 e8???????? 83c40c 84c0 74a0 8a442413 }

	condition:
		7 of them and filesize <90112
}