rule MALPEDIA_Win_Unidentified_039_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "79803854-9c28-5ee4-826a-7f1227d74ba5"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_039"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.unidentified_039_auto.yar#L1-L126"
		license_url = "N/A"
		logic_hash = "58c8fb21d6ae978d62ed7528cfbdb8da381c56d520ca5623fbbc73c80d3173d3"
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
		$sequence_0 = { b8???????? e8???????? 8365fc00 8365cc00 c745dce7600000 c745ec89640000 }
		$sequence_1 = { c745f00b090000 c745f089000000 8975c0 c745f4b76e0000 c745fc9e540000 c745f8a7600000 }
		$sequence_2 = { c74530284c0000 c7453425120000 c745281f480000 c74538136b0000 c74520825d0000 c7451c84360000 8b4530 }
		$sequence_3 = { 69c9de3f0000 33c1 8945dc 8b4510 8b4d0c 3bc8 7d0c }
		$sequence_4 = { 8bec 51 51 c745f81d2d0000 c745f8d33a0000 c745fc9a790000 }
		$sequence_5 = { c745d0e5720000 8b45d0 8b4dd4 0fafc1 8b4dd8 8b55dc }
		$sequence_6 = { 6bc01f c1e704 83c30c 03fa 33d2 }
		$sequence_7 = { 69c0295a0000 8945e4 e8???????? c745e0f9750000 c745f0b56c0000 c745ec29110000 }
		$sequence_8 = { 8d45f4 64a300000000 c3 6a00 6a01 ff74240c }
		$sequence_9 = { c745e863430000 8b45e4 59 8b4df8 23c1 8b4de8 81e931570000 }

	condition:
		7 of them and filesize <262144
}