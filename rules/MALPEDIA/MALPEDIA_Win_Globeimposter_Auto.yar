
rule MALPEDIA_Win_Globeimposter_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "4d7b48e1-c009-5b34-a438-f100a6a58894"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.globeimposter"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.globeimposter_auto.yar#L1-L116"
		license_url = "N/A"
		logic_hash = "608bf851e6cd1f78be1de6e26308954d73fd642b69ffa80c802e22a056e6ef77"
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
		$sequence_0 = { c1e810 8bca c1e908 23c7 23cf }
		$sequence_1 = { 6a0c 5f eb0d 3d96000000 1bff }
		$sequence_2 = { 8b4508 8b4e08 89442418 85ff 7452 }
		$sequence_3 = { 0fd4cd 0f6e6f10 0fd4d5 0f7e4f08 0f73d120 0fd4cf 0f6e6f14 }
		$sequence_4 = { 6a02 57 57 6800000040 8d85fcefffff }
		$sequence_5 = { 0fd4cb 0f6e16 0ff4d0 0f6e6604 }
		$sequence_6 = { 83c0fc 3918 7506 83e804 4f 75f6 }
		$sequence_7 = { 83c104 f7db 75d7 5f 5b }
		$sequence_8 = { 8bf0 8b06 8d7604 0119 3919 }
		$sequence_9 = { 8bc7 f7f6 33d2 0fafc6 2bf8 }

	condition:
		7 of them and filesize <327680
}