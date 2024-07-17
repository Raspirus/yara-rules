
rule MALPEDIA_Win_Selfmake_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "ca04d6b7-e045-5526-8793-d9e1e0d359e9"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.selfmake"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.selfmake_auto.yar#L1-L122"
		license_url = "N/A"
		logic_hash = "c57531acfc321c5fdc74a4f21330394c8edf44f2f30ab3dcaf573b2b773dc0b6"
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
		$sequence_0 = { 83c104 3bf0 7ce3 68???????? }
		$sequence_1 = { 83e107 894df4 8b55f4 52 ff15???????? a1???????? 8be5 }
		$sequence_2 = { 8d742430 742e e8???????? 6aff }
		$sequence_3 = { 47 84c0 75f8 66a1???????? 668907 8d44243c 8bd0 }
		$sequence_4 = { 8945f8 837df800 7408 8b45f8 e9???????? e8???????? }
		$sequence_5 = { 8b4b2c 6a00 6a01 51 ffd0 8b16 83c604 }
		$sequence_6 = { 7604 2bf1 eb02 33f6 8b4310 25c0010000 83f840 }
		$sequence_7 = { 81fa???????? 7209 83c014 3bc1 72eb }
		$sequence_8 = { 51 e8???????? 8b742418 8bbc2418020000 }
		$sequence_9 = { e8???????? 56 e8???????? 8b442424 8b35???????? 83c414 50 }

	condition:
		7 of them and filesize <932864
}