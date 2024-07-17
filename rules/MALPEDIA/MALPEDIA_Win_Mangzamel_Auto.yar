rule MALPEDIA_Win_Mangzamel_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "efd17f11-bd84-5994-8489-ce27d4f0f0e6"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mangzamel"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.mangzamel_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "e3b6cc187254084e27045992bdf0d8b8ff879105635bf8f3e82d14e2723774a4"
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
		$sequence_0 = { 8b7508 837e1410 7404 32c0 eb6e 8b06 53 }
		$sequence_1 = { 8d8dd4feffff e8???????? 33db 8d8dc0fdffff 895dfc e8???????? 8d85d4feffff }
		$sequence_2 = { 6a00 8bce ff7674 e8???????? 6a01 6804000102 8bce }
		$sequence_3 = { ff7508 e8???????? 84c0 7404 c645f301 8b4df4 }
		$sequence_4 = { 8bd0 8b00 8b5208 3932 7506 837a0400 }
		$sequence_5 = { e8???????? 33c0 8bce 50 50 50 ff742414 }
		$sequence_6 = { 8bce ff7508 ff5040 8ac3 5e 5b 5d }
		$sequence_7 = { 57 8b7c2414 33c0 8907 8b0d???????? 3bc8 }
		$sequence_8 = { 8d4b6c e8???????? 5e 5b c3 56 8bf1 }
		$sequence_9 = { 8b74240c 57 8b7c240c 8d4602 50 57 e8???????? }

	condition:
		7 of them and filesize <360448
}