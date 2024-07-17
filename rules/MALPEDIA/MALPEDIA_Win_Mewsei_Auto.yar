
rule MALPEDIA_Win_Mewsei_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "78bf6ca7-ef3d-53c3-89fb-bc5bc524aac5"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mewsei"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.mewsei_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "3736165e5248449b2b75237b3807b31270781b320dfabe4092f7167612f74bb7"
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
		$sequence_0 = { 337df8 8b5dfc 237df4 337df0 037dc0 8dbc1faf0f7cf5 }
		$sequence_1 = { e8???????? 50 8bc7 e8???????? 83c404 e8???????? 50 }
		$sequence_2 = { 0fbe7c0602 57 e8???????? 83c404 85c0 7405 8d47d0 }
		$sequence_3 = { 8b4610 8b0cb8 8911 8b55f8 }
		$sequence_4 = { 57 e8???????? 8b1d???????? 83c410 6a00 }
		$sequence_5 = { 83c404 895df8 85db 750c 6a01 e8???????? 83c404 }
		$sequence_6 = { 6a01 6a0e 56 ff15???????? }
		$sequence_7 = { 6a04 8d4df8 51 6a04 6a00 56 }
		$sequence_8 = { ff15???????? 57 8bf0 53 56 ff15???????? 50 }
		$sequence_9 = { 337df4 337dfc 037dcc 8dbc1ff87ca21f 8b5df0 c1c710 }

	condition:
		7 of them and filesize <504832
}