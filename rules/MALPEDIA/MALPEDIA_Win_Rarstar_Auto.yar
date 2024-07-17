
rule MALPEDIA_Win_Rarstar_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "1b0cea37-0a1d-5e66-91fc-944e4e50541c"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rarstar"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.rarstar_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "2e522865d24e8dea587d8aa292c78791c9371361cc03d604920c80f6d8c9bb83"
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
		$sequence_0 = { 8a5e01 83e203 c1fb04 c1e204 }
		$sequence_1 = { 33d2 b903000000 f7f1 83c408 8bc6 }
		$sequence_2 = { 85ed 7e6f 8a143e 83c703 c1fa02 83e23f 41 }
		$sequence_3 = { 0f84c1010000 8b2d???????? 8b4c2434 8b54241c 6a00 }
		$sequence_4 = { 33db 8a940c24010000 8a5c0c24 03c2 03c3 25ff000080 }
		$sequence_5 = { ffd6 8d84241c020000 68???????? 50 ffd6 8d8c2424040000 68???????? }
		$sequence_6 = { 8d8c2420030000 51 52 ffd5 8d842418010000 68???????? }
		$sequence_7 = { 899c242c030000 899c2428030000 899c2424030000 899c2420030000 bf???????? 83c9ff }
		$sequence_8 = { f7d1 2bf9 899c2430030000 8bc1 8bf7 8bfa }
		$sequence_9 = { 8a9405ecfdffff 8890a0d74000 eb1c f6c202 7410 8088????????20 8a9405ecfcffff }

	condition:
		7 of them and filesize <122880
}