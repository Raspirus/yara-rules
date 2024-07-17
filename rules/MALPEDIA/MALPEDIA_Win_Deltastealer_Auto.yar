rule MALPEDIA_Win_Deltastealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "e4bcf99b-e757-5705-a59b-a0722820f3d9"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.deltastealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.deltastealer_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "f3a202dde71406be69325c7d8bb3b580aed323825ecf5c600f5b385fd3e3e19c"
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
		$sequence_0 = { 4883c428 c3 56 57 53 4883ec30 4c89c6 }
		$sequence_1 = { 4d01c1 4c894c2420 4c89442428 c744243803001100 c744244803001100 488d5c2430 4c8d742440 }
		$sequence_2 = { 57 53 4883ec40 4889d3 488b01 488b7008 488b7810 }
		$sequence_3 = { 84c0 7416 4180bc240802000000 750b 488b842448010000 c60001 4584f6 }
		$sequence_4 = { e8???????? 498b7610 31db 4839df 741e 8a041e 8d48bf }
		$sequence_5 = { 89d7 48ffc3 49895e10 49f7e2 0f80a8000000 400fb6d7 4801d0 }
		$sequence_6 = { c6474001 4889f9 e8???????? 4885c0 7438 4885d2 7433 }
		$sequence_7 = { e8???????? 4489e3 488d4c2460 e8???????? 4989c7 eb21 4584e4 }
		$sequence_8 = { 48895c2420 488d7c2430 41b830000000 41b910000000 4889f9 e8???????? 488b7f18 }
		$sequence_9 = { 6601c8 0f92c2 81f9ffff0000 0f87d8feffff 84d2 0f85d0feffff 4d85f6 }

	condition:
		7 of them and filesize <3532800
}