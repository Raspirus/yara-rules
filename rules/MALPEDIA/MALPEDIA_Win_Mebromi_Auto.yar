
rule MALPEDIA_Win_Mebromi_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "e0d98380-a60b-51d2-98f3-302d440340e7"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mebromi"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.mebromi_auto.yar#L1-L125"
		license_url = "N/A"
		logic_hash = "4361b37a1cf79aacd380ae78b2f2e74bbc44d101b09510c6583cf0529e44be88"
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
		$sequence_0 = { 743a 837d0800 742e 85f6 7419 0fb6da f68301a0290004 }
		$sequence_1 = { 68ff010f00 68???????? ff742410 ff15???????? 8bf0 85f6 7416 }
		$sequence_2 = { 7714 8b55fc 8a9270722900 089001a02900 }
		$sequence_3 = { 683f000f00 55 55 ff15???????? 8bf0 e8???????? 56 }
		$sequence_4 = { 48 750c e8???????? eb05 e8???????? 6a01 }
		$sequence_5 = { 0fb6fa 3bc7 7714 8b55fc 8a9270722900 089001a02900 }
		$sequence_6 = { 2c29 0000 2d29008a46 0323 d18847034ec1 e9???????? }
		$sequence_7 = { 0fb6d2 f68201a0290004 740c ff01 }
		$sequence_8 = { aa 8d9e88722900 803b00 8bcb 742c 8a5101 84d2 }
		$sequence_9 = { 50 6a01 56 ff15???????? 56 8bf8 ff15???????? }

	condition:
		7 of them and filesize <106496
}