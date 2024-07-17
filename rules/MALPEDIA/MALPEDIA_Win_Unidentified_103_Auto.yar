
rule MALPEDIA_Win_Unidentified_103_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "16a9604f-a791-56b5-96cf-005a08b625a2"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_103"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.unidentified_103_auto.yar#L1-L128"
		license_url = "N/A"
		logic_hash = "ea0101ff935636b4e103b28ee875e3c3a8b80a54f2863e597f7dff9a335e50db"
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
		$sequence_0 = { 85db 0f8506030000 8b442470 ffd0 8b542478 81c41c070000 }
		$sequence_1 = { 8954240c 8b9424e4000000 89742404 83ea04 89542408 8b8404cc0b0000 8b00 }
		$sequence_2 = { 83ec08 85c0 7439 8b8424bc010000 890424 8b44246c ffd0 }
		$sequence_3 = { 0fb613 89c3 8d6c11e0 01d1 }
		$sequence_4 = { 890424 8b842488000000 ffd0 83ec08 8b842484010000 890424 8b8424a4000000 }
		$sequence_5 = { 31db ffd6 c684249803000000 898424bc000000 b878650000 6689842496030000 b865000000 }
		$sequence_6 = { c744240804000000 89442404 8b842484010000 890424 8b8424ac000000 ffd0 }
		$sequence_7 = { 0f84d3070000 81fd03030000 0f85d5060000 8b842484010000 c744240402000000 89fb be01000000 }
		$sequence_8 = { 8bb4244c010000 01ca 880431 0fb68424a5010000 8844290a 0fb68424a6010000 8844290b }
		$sequence_9 = { 83ec08 0fb68c2450040000 84c9 741f 31d2 83c201 }

	condition:
		7 of them and filesize <188416
}