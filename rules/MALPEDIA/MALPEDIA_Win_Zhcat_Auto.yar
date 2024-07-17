
rule MALPEDIA_Win_Zhcat_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "0ba2d083-15f8-52b3-8a0e-523b48182ccb"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zhcat"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.zhcat_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "42a0cd82873743b61553ad212467ec7353604cc191810d2e10195e3fc58baf2d"
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
		$sequence_0 = { 8b3d???????? 8b7508 4f 8945fc }
		$sequence_1 = { 741e 8d45f8 8975f8 50 85ff 750a }
		$sequence_2 = { 85c9 759e 56 e8???????? 59 }
		$sequence_3 = { 85c9 759e 56 e8???????? 59 5f 5e }
		$sequence_4 = { 3c74 7404 3c54 7512 8915???????? eb0a }
		$sequence_5 = { 68???????? 56 56 897004 ffd3 6aff }
		$sequence_6 = { ff7508 ff15???????? ff7514 8945e4 8bc7 668945f0 ffd6 }
		$sequence_7 = { eb28 c705????????02000000 eb1c c605????????01 }
		$sequence_8 = { 0fb63e 0fb6c0 eb12 8b45e0 8a80044a4100 08443b1d 0fb64601 }
		$sequence_9 = { ff7508 ff15???????? 57 8bf0 e8???????? 59 5f }

	condition:
		7 of them and filesize <376832
}