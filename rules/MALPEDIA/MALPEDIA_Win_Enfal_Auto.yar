rule MALPEDIA_Win_Enfal_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "7c648ee2-e4dd-541c-9b47-28a132a1416c"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.enfal"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.enfal_auto.yar#L1-L112"
		license_url = "N/A"
		logic_hash = "4106f1f3c4e35436925009af22c1e6b23f6200a61794638682b09644acc42fa2"
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
		$sequence_0 = { ffd6 68???????? 57 8945d8 ffd6 68???????? 53 }
		$sequence_1 = { 51 53 ff505c 85c0 }
		$sequence_2 = { 50 6a00 6a01 ff7608 }
		$sequence_3 = { 57 6800000040 51 ff5010 8bd8 }
		$sequence_4 = { 81ec4c0a0000 80a5b4f9ffff00 56 baff000000 }
		$sequence_5 = { 8b4b24 8b431c 8b5320 8365fc00 }
		$sequence_6 = { 50 e8???????? 83c410 8b461c }
		$sequence_7 = { 8bec 81eccc040000 53 56 8b35???????? 57 }
		$sequence_8 = { ffd0 5e c3 ff15???????? 5e c3 }
		$sequence_9 = { 66a5 a4 be???????? 8dbd60ffffff }

	condition:
		7 of them and filesize <65536
}