rule MALPEDIA_Win_Chairsmack_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "89ef8364-1d04-5ec8-8eb0-0caa1f808e4e"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chairsmack"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.chairsmack_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "30e742a004c4313020160ca17f15835b780b5f554d2c7d95b7655ea180005855"
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
		$sequence_0 = { 8d8c2410010000 c68424840300003a e8???????? 83ec1c 8d842428010000 8bcc 8964242c }
		$sequence_1 = { 8d4de8 56 c745fc01000000 e8???????? 8b7df0 8d4de8 2b7e08 }
		$sequence_2 = { 8d4c2464 e8???????? e9???????? 68???????? 8d8c24bc000000 e8???????? 8bd0 }
		$sequence_3 = { 8b4004 eb03 83c004 51 50 ffb4249c000000 51 }
		$sequence_4 = { 660f57c4 8b7c2414 8d442421 c644242025 8b5714 f6c220 7409 }
		$sequence_5 = { 7613 b8feffff7f 8d3419 2bc1 3bd8 7605 befeffff7f }
		$sequence_6 = { 8d8db8fcffff e9???????? 8d8dd0fdffff e9???????? 8d8dbcfcffff e9???????? 8d8dc0fdffff }
		$sequence_7 = { c68424b8030000b9 8bcc 68???????? e8???????? c68424b8030000b6 e8???????? 83c430 }
		$sequence_8 = { 8b148dd06d4a00 81c200080000 3955e4 7366 8b45e4 c6400400 8b4de4 }
		$sequence_9 = { 0fbe02 85c0 0f848e010000 8b4dfc 51 }

	condition:
		7 of them and filesize <1974272
}