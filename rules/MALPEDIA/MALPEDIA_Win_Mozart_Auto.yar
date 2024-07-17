rule MALPEDIA_Win_Mozart_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "1438b6f5-0fc9-5eca-9ae3-36eb59239394"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mozart"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.mozart_auto.yar#L1-L124"
		license_url = "N/A"
		logic_hash = "94b0456ee335dcdb1592bd3a0f2b861e74a91bd5433e8fc753965fb9891ac5e3"
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
		$sequence_0 = { 7c26 80fb39 7f21 885c3418 46 }
		$sequence_1 = { 66ab e8???????? 8d44242c 50 e8???????? 8d8c2430010000 51 }
		$sequence_2 = { c1f805 8d1c85c0db4000 8b03 8bf1 83e61f c1e603 8a443004 }
		$sequence_3 = { 49 7438 49 7471 c1e006 0bc7 }
		$sequence_4 = { 55 8bec 83e4f8 81ec20020000 a1???????? 8b0d???????? 668b15???????? }
		$sequence_5 = { 8bf0 83e61f 8d3c8dc0db4000 8b0f c1e603 f644310401 7455 }
		$sequence_6 = { 8a08 40 84c9 75f9 8b8c2420100000 }
		$sequence_7 = { 2bc7 3bf0 7202 33f6 8bc5 43 42 }
		$sequence_8 = { 8b0a 83c502 3be9 7728 }
		$sequence_9 = { 751a 84c0 7426 8b5608 47 }

	condition:
		7 of them and filesize <114688
}