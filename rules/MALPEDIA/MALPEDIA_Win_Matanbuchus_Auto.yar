rule MALPEDIA_Win_Matanbuchus_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "2788ba99-d4a7-56bc-b166-5140402f53be"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.matanbuchus"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.matanbuchus_auto.yar#L1-L115"
		license_url = "N/A"
		logic_hash = "78ecf15a99d40895d657b9372a7af5a206c5b9d4887dbdf8360368c6bcd36a27"
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
		$sequence_0 = { 038c0534fdffff 51 e8???????? ebb4 8b55fc 52 e8???????? }
		$sequence_1 = { 6a0c 6a0c 68???????? e8???????? }
		$sequence_2 = { 8b4dfc 038c0534fdffff 51 e8???????? }
		$sequence_3 = { 8b4df8 8b513c 035508 8955f4 }
		$sequence_4 = { 6bc200 8b4d08 0fbe1401 33550c }
		$sequence_5 = { 68f8000000 8d95b8feffff 52 8b45fc 0345ec 50 e8???????? }
		$sequence_6 = { 8b45f4 c1e818 3345f4 8945f4 694df495e9d15b 894df4 }
		$sequence_7 = { 51 8b55f0 52 6b45f828 8b4dfc 038c0534fdffff }
		$sequence_8 = { eb44 b901000000 d1e1 8b55ec }
		$sequence_9 = { 8b55ec 813a50450000 7407 33c0 e9???????? }

	condition:
		7 of them and filesize <2056192
}