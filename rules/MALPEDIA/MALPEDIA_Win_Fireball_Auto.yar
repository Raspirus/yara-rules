
rule MALPEDIA_Win_Fireball_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "41b2d4de-af91-5e95-ba91-5bc661ef7417"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fireball"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.fireball_auto.yar#L1-L120"
		license_url = "N/A"
		logic_hash = "0f627ea55086f489b8cd11c65d68f2e0680aa8b1619660718f20b28106c4357c"
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
		$sequence_0 = { 52 8bce e8???????? b101 e8???????? }
		$sequence_1 = { 30a830ac30b0 30b830cc30e8 30f0 30f4 3010 3118 311c31 }
		$sequence_2 = { 8b0f 8bc1 c1f805 83e11f 8b0485000a2500 c1e106 80640804fe }
		$sequence_3 = { 68???????? 8d8c24a4000000 c78424b800000007000000 c78424b400000000000000 }
		$sequence_4 = { c78424a400000000000000 6689842494000000 837c247808 720c ff742464 e8???????? }
		$sequence_5 = { 53 ff15???????? 85c0 0f85c2feffff }
		$sequence_6 = { c78518f5ffff07000000 c78514f5ffff00000000 66898504f5ffff 83bdf4f5ffff08 720e }
		$sequence_7 = { c68558fbffff00 7504 33c9 eb12 8d8d64f9ffff }
		$sequence_8 = { 8d442417 50 8d542434 8d8c2498000000 c744244c07000000 c744244800000000 e8???????? }
		$sequence_9 = { 8bf1 c785e8fbffff00000000 e8???????? 83c40c 8d85ecfbffff 6808020000 }

	condition:
		7 of them and filesize <335872
}