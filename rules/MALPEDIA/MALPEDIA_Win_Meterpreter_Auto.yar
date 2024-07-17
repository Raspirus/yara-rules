
rule MALPEDIA_Win_Meterpreter_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "94296578-89d7-5d7b-b7e4-efe037d64332"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.meterpreter"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.meterpreter_auto.yar#L1-L125"
		license_url = "N/A"
		logic_hash = "71f865d4008295f79c7afc49beb427fb0376821d7b27897466868baff3347cd2"
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
		$sequence_0 = { 55 8bec dcec 088b55895356 108b3a85ff89 7dfc 750e }
		$sequence_1 = { fc b8c0150000 8b7508 33e5 257e040275 238b1d6a016a 006a00 }
		$sequence_2 = { f1 57 52 bc40e84fff 38ff 83db14 5f }
		$sequence_3 = { 314319 034319 83ebfc 0acb }
		$sequence_4 = { 0000 68ffff0000 52 ffd7 8b2410 }
		$sequence_5 = { 8be5 5d c27f00 8d4df4 8d55ec }
		$sequence_6 = { 51 6a00 6a00 37 0052bf 15???????? 85c0 }
		$sequence_7 = { 8b451c 8d07 a4 52 8d4d18 50 }
		$sequence_8 = { 41 00ff 15???????? 33c0 c3 7790 55 }
		$sequence_9 = { 83ec08 53 8b4708 57 33ff 85db }

	condition:
		7 of them and filesize <188416
}