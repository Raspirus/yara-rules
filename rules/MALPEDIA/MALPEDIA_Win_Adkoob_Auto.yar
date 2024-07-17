
rule MALPEDIA_Win_Adkoob_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "09ef20a4-923f-52b9-be25-7277d044ed19"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.adkoob"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.adkoob_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "0f163717fb5860f8982d25c9dbbe18c357f664ad9d46a5bfca06cc794c00bf30"
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
		$sequence_0 = { ff706c ffb0b0000000 8bc7 6a14 59 99 f7f9 }
		$sequence_1 = { ff75f0 6a38 5a e8???????? 83c40c 8bce 40 }
		$sequence_2 = { 8d5801 e9???????? 53 8bcf e8???????? 8b5dd8 84c0 }
		$sequence_3 = { 8955f8 8b90d4000000 0fb6443b06 c1e108 0bc8 897de8 2bf1 }
		$sequence_4 = { ff504c 85c0 7536 8b75dc 56 ff15???????? 50 }
		$sequence_5 = { 8b7508 83fe09 7756 80beac1d4c0000 57 8b3d???????? 0f453d???????? }
		$sequence_6 = { ff75e8 ff15???????? 837dd000 8b35???????? 7405 ff75d0 ffd6 }
		$sequence_7 = { ff742418 68???????? e8???????? 83c40c 89442428 85c0 747b }
		$sequence_8 = { ff7510 8bce ffb578ffffff ff75b8 ff7598 ffb564ffffff ff75c4 }
		$sequence_9 = { 8b4744 52 50 8b08 ff5114 59 59 }

	condition:
		7 of them and filesize <1867776
}