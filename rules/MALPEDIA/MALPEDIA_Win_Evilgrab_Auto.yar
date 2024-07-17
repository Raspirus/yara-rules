
rule MALPEDIA_Win_Evilgrab_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "92d56cb6-a40e-55a9-bb4b-7f3303d7e68c"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.evilgrab"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.evilgrab_auto.yar#L1-L127"
		license_url = "N/A"
		logic_hash = "89c0b96a8a59594e704b0e35c7d209399933043505a45ecc6b5a8cd70ad1865a"
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
		$sequence_0 = { 50 50 50 52 89442440 89442434 89442438 }
		$sequence_1 = { 8dbdb8f5ffff f3a5 a4 b909000000 be???????? 8dbd5cf4ffff f3a5 }
		$sequence_2 = { c3 8d45c4 50 6a03 68???????? 8b0e 81c1d2000000 }
		$sequence_3 = { 8b9534aeffff 52 8bcb e8???????? 85c0 7531 6aa7 }
		$sequence_4 = { 8b35???????? e9???????? 8b85c8adffff 898540a3ffff 50 e8???????? 8b85c0adffff }
		$sequence_5 = { 6a00 85f6 6a00 7567 }
		$sequence_6 = { 52 8b45d4 8b481c 51 e8???????? }
		$sequence_7 = { 52 8b35???????? ffd6 d1e0 898565a4ffff }
		$sequence_8 = { 52 68???????? 53 ffd5 83c410 6880000000 53 }
		$sequence_9 = { 33c0 8dbdf0efffff f3ab c685f0efffffd0 668b5304 52 e8???????? }

	condition:
		7 of them and filesize <327680
}