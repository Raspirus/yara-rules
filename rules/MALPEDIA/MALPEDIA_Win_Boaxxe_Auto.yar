
rule MALPEDIA_Win_Boaxxe_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "d2861d72-2434-5a6e-bbf4-9290c68bd235"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.boaxxe"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.boaxxe_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "232a66e4610caa68487a07fb0b6c51bc622cacc6954ed1eec17df693514e555a"
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
		$sequence_0 = { b904000000 e8???????? 8d55c4 66b8c503 e8???????? 8b55c4 a1???????? }
		$sequence_1 = { 0f8c88000000 8d4df4 8b55f8 8b45f8 e8???????? 8b55f4 8d45f8 }
		$sequence_2 = { 83c220 8d45f8 e8???????? 8d45f8 e8???????? 8945f4 8b45f4 }
		$sequence_3 = { 33c0 55 68???????? 64ff30 648920 8bcb b230 }
		$sequence_4 = { 85db 7410 8b55f4 8b45ec 8bcb e8???????? }
		$sequence_5 = { 8b45cc e8???????? 8bd8 891d???????? 891d???????? 8d45c8 50 }
		$sequence_6 = { 01d0 c1e003 8b803c58bc6d 8945ec e9???????? 837de808 }
		$sequence_7 = { a1???????? e8???????? 8bd0 53 8bc2 e9???????? 33c0 }
		$sequence_8 = { 0342fc 8945ec 8b45f8 8b00 8b5508 0342fc 8945f0 }
		$sequence_9 = { b808000000 e8???????? 8b55f8 58 e8???????? 7504 33db }

	condition:
		7 of them and filesize <1146880
}