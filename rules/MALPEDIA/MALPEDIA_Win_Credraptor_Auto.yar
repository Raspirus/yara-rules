
rule MALPEDIA_Win_Credraptor_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "744ed2ca-2dde-53b2-b19d-4369cb84cbb1"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.credraptor"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.credraptor_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "751cbf31cf2ad7ebff2dead521605a0ec12dc4ff6ec97fefa5bfc3c13ba5bce0"
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
		$sequence_0 = { bb???????? 8bf8 e8???????? 8945fc 8b45f8 83c408 85c0 }
		$sequence_1 = { c6402597 895028 8b5120 89502c 8bce 8bc3 e8???????? }
		$sequence_2 = { 8d4db4 e8???????? 85c0 754b 8d55b4 52 e8???????? }
		$sequence_3 = { b800020000 660bc8 8b45f8 5f 894604 894624 66894e1c }
		$sequence_4 = { a900050000 7565 837b1c00 745f 8b4df8 8b5110 52 }
		$sequence_5 = { 8b8e14020000 8975f0 895df8 e8???????? 8bf8 83c404 897dfc }
		$sequence_6 = { 8db5c8fdffff e8???????? 85c0 7430 8b8dccfdffff 8b7f0c 8b95c8fdffff }
		$sequence_7 = { 894d94 8bff 8a01 dd8574ffffff dd05???????? 3c25 7409 }
		$sequence_8 = { c7461000000000 53 c60600 e8???????? 83c404 807f4100 8bdf }
		$sequence_9 = { bb07000000 85ff 7439 ba60240000 6685571c 7409 57 }

	condition:
		7 of them and filesize <1728512
}