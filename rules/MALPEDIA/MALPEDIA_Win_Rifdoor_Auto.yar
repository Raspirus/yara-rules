
rule MALPEDIA_Win_Rifdoor_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "10650b5d-c263-58c2-9892-48c8752426d4"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rifdoor"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.rifdoor_auto.yar#L1-L174"
		license_url = "N/A"
		logic_hash = "041eb6ebe0e6f7a680f9d10fa1b95fdf41bb567152330eaf4a0d973e56aa2474"
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
		$sequence_0 = { e8???????? 8be5 5d c20400 6804010000 8d54240c }
		$sequence_1 = { 0f8484000000 391d???????? 747c 391d???????? 7474 391d???????? 746c }
		$sequence_2 = { ba4f000000 8bc2 668944243c b952000000 66894c2438 668954243a }
		$sequence_3 = { 83c408 85c0 7405 bf01000000 8d542410 52 ff15???????? }
		$sequence_4 = { 830eff 2b34bd605d4100 c1fe06 8bc7 c1e005 }
		$sequence_5 = { b001 5e 81c408010000 c3 5f 32c0 }
		$sequence_6 = { 8d4c2454 51 8b4c2410 8d54242c e8???????? 83c408 85c0 }
		$sequence_7 = { 83c408 a3???????? e9???????? 3c01 }
		$sequence_8 = { 53 56 8b35???????? 57 3b35???????? 7d4a }
		$sequence_9 = { 50 8b410c ffd0 8b95f0f7ffff }
		$sequence_10 = { e8???????? 8b1d???????? 33c0 83c40c 33d2 }
		$sequence_11 = { 68ff000000 8d9524faffff 52 ff15???????? }
		$sequence_12 = { 75f9 8d8de8fbffff 2bc2 51 40 }
		$sequence_13 = { c1ee08 0bd6 884101 03c2 8d1400 33d0 }
		$sequence_14 = { ff15???????? 68???????? 6a00 6801001f00 ff15???????? 5f 5e }
		$sequence_15 = { 8d8424a8010000 50 53 ff15???????? 85c0 7507 53 }

	condition:
		7 of them and filesize <212992
}