
rule MALPEDIA_Win_Crypto_Fortress_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "6a23a7a3-8360-570b-be01-5aa731924fe0"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crypto_fortress"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.crypto_fortress_auto.yar#L1-L126"
		license_url = "N/A"
		logic_hash = "cb9e8ad6d0528bcc920d7d8992919925e873e6ab7fd21de603b21e974fe6d2be"
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
		$sequence_0 = { ffb5a8feffff e8???????? 68???????? ffb5a8feffff e8???????? }
		$sequence_1 = { a3???????? 68???????? ff35???????? e8???????? 85c0 0f846f030000 }
		$sequence_2 = { aa 3407 aa 045a aa }
		$sequence_3 = { e8???????? 85c0 0f846f030000 a3???????? 68???????? ff35???????? e8???????? }
		$sequence_4 = { ff35???????? e8???????? 85c0 0f8456060000 a3???????? 8d3dccec4000 33c0 }
		$sequence_5 = { 2cff aa 2cf9 aa 2c4c }
		$sequence_6 = { aa 2c4e aa 0444 aa 2cff aa }
		$sequence_7 = { c9 c20800 55 8bec 83c4f8 8b4508 }
		$sequence_8 = { aa 341b aa 2c27 aa 3441 aa }
		$sequence_9 = { aa 340a aa 3421 aa 0433 aa }

	condition:
		7 of them and filesize <188416
}