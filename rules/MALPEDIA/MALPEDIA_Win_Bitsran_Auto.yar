
rule MALPEDIA_Win_Bitsran_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "e3cfbc68-7ec2-5ca7-89d3-b794638917c8"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bitsran"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.bitsran_auto.yar#L1-L119"
		license_url = "N/A"
		logic_hash = "2919e184e2a9722abe679cf353ecc217eb2b7fdd010f4e63772073cd0ac5e798"
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
		$sequence_0 = { 85c0 7433 56 57 8bbdf8bfffff c1ef02 }
		$sequence_1 = { 8911 8b0d???????? 8b9d58fdffff eb5e 8b35???????? }
		$sequence_2 = { 85f6 7417 8b4508 50 }
		$sequence_3 = { 50 53 e8???????? 8b9d44fdffff 83ef04 }
		$sequence_4 = { 83c408 85c0 7403 8975fc 8b03 8d55b8 52 }
		$sequence_5 = { 742b 8bc1 2bc1 c1f802 8d348500000000 }
		$sequence_6 = { 8b04c5046f4100 5d c3 8bff }
		$sequence_7 = { 8d95d4fbffff 52 53 ff15???????? 837d1401 7407 }
		$sequence_8 = { 2bc3 c1f802 3dfeffff3f 0f87d0010000 8bca 2bcb }
		$sequence_9 = { 899d58fdffff 3bd9 0f83fe000000 3bd3 0f87f6000000 8b35???????? 2bda }

	condition:
		7 of them and filesize <344064
}