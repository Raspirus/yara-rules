rule MALPEDIA_Win_Dramnudge_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "4e1e9905-62de-5567-9ed7-a82928870a8c"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dramnudge"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.dramnudge_auto.yar#L1-L90"
		license_url = "N/A"
		logic_hash = "221dd8bcd930b6121a924fbe6761de15c83c657ddce0c9178183beb8828f75f7"
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
		$sequence_0 = { 014218 eb18 03c3 8bd3 }
		$sequence_1 = { 000c00 20b140005f5f 7277 7374 }
		$sequence_2 = { 014318 8b430c 2b4308 03c6 }
		$sequence_3 = { 000c00 e0d9 40 007374 }
		$sequence_4 = { 014318 8b4318 8b55f8 03d6 }
		$sequence_5 = { 007374 643a3a 7275 6e }
		$sequence_6 = { 0000 90 000c00 20b140005f5f }
		$sequence_7 = { 014318 eb5b 33f6 eb01 }

	condition:
		7 of them and filesize <1294336
}