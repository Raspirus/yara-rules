rule MALPEDIA_Win_Webc2_Bolid_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "05fc3e6a-bc1e-5e27-996e-6357de6a9e2c"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_bolid"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.webc2_bolid_auto.yar#L1-L120"
		license_url = "N/A"
		logic_hash = "938464f6c09d72401fc04aa41413a321a3c389b634663fb70512029f39441d8b"
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
		$sequence_0 = { 741e 8b4c240c 51 ff15???????? 56 68???????? e8???????? }
		$sequence_1 = { e8???????? 8d8c24d4000000 c684242c02000004 51 8bcd e8???????? 8b15???????? }
		$sequence_2 = { 8bcb e8???????? 85c0 0f84fa000000 8b550c 42 }
		$sequence_3 = { 49 885c2454 51 68???????? 8d4c2444 }
		$sequence_4 = { 83c40c 8b15???????? 8d4de4 52 }
		$sequence_5 = { e8???????? 6a01 8d4c2440 c644245800 e8???????? 8b4c2460 }
		$sequence_6 = { f3a4 8b35???????? 8d4c2410 51 6a26 52 89442420 }
		$sequence_7 = { 8b458c 3bc3 7505 b8???????? }
		$sequence_8 = { 50 ff5104 33db 6a01 }
		$sequence_9 = { 53 880e 8bce e8???????? 8b15???????? 8d44245c }

	condition:
		7 of them and filesize <163840
}