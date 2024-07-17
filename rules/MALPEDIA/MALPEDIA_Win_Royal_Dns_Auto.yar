
rule MALPEDIA_Win_Royal_Dns_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "8e27ee32-9aaf-59db-953d-0696af40bcce"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.royal_dns"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.royal_dns_auto.yar#L1-L119"
		license_url = "N/A"
		logic_hash = "f281d4e3be759adcb32b06448d83aa5fdafcb96a4b912bbb46b43de4955e29ec"
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
		$sequence_0 = { 50 e8???????? 8b4dfc 8b85b4fcffff 83c404 }
		$sequence_1 = { e8???????? 83c40c 8bc6 eb15 8d8da1f1ffff }
		$sequence_2 = { ff15???????? 3d02010000 8b85e0fdffff 7533 6a00 50 }
		$sequence_3 = { 4a 759a 8b55fc 85ff 7468 0fb606 c1e802 }
		$sequence_4 = { 0fb61406 c1ea03 0fb69248132500 8811 0fb61c06 0fb6540601 c1ea06 }
		$sequence_5 = { 80e301 0ac3 8845ed 8a45f8 8ad8 8345e805 }
		$sequence_6 = { 8d8dfcfeffff 83c40c 33c0 2bd1 }
		$sequence_7 = { 7504 33c0 eb0a 0fb6c8 }
		$sequence_8 = { 0fb61c30 0fb6543001 03db 03db c1ea06 0bd3 }
		$sequence_9 = { 8a17 8816 47 46 48 }

	condition:
		7 of them and filesize <204800
}