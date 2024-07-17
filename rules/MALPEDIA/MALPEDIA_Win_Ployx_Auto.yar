
rule MALPEDIA_Win_Ployx_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "7a9ae933-1e52-56f8-912b-cfaf3c1a4d79"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ployx"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.ployx_auto.yar#L1-L127"
		license_url = "N/A"
		logic_hash = "92d48577836748eb447c5a838f0c9893d40b34aa95d5979c4991a0399ec4439d"
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
		$sequence_0 = { 8bc3 25ff000000 59 3bf0 59 7443 }
		$sequence_1 = { 33db 897df8 e8???????? 397dfc 59 59 }
		$sequence_2 = { 33ff 59 85c0 7e19 8bf0 8bfe 6a20 }
		$sequence_3 = { 66ab ff35???????? aa 8d8588faffff 68???????? 50 }
		$sequence_4 = { 8d3c78 8d0437 50 e8???????? 8b4d08 8d3c78 8d0437 }
		$sequence_5 = { b9???????? b800020000 8d5f02 99 f7fb 47 8901 }
		$sequence_6 = { 33ff 99 59 f7f9 8bc2 03c1 99 }
		$sequence_7 = { 59 8945f4 0f848f000000 8d45e8 50 }
		$sequence_8 = { e8???????? 83c40c 8d85a4fcffff 6a00 50 ff15???????? 8945e8 }
		$sequence_9 = { 740f 3b7df8 7503 8975f8 57 }

	condition:
		7 of them and filesize <229376
}