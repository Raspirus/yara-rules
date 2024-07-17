rule MALPEDIA_Win_Acehash_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "14f9c3a4-6e4e-554e-b1b7-7826b028e7e0"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.acehash"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.acehash_auto.yar#L1-L130"
		license_url = "N/A"
		logic_hash = "a82974d1f4758bd3335b7cc99825d249f1ec423d226c32410d6047b493cb8d39"
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
		$sequence_0 = { 4885c0 7420 488d1599dc0200 488bcb ff15???????? 488bc8 }
		$sequence_1 = { 85c0 0f85e6000000 4c8b470c 488b55d0 488b4f04 ff15???????? 8bd8 }
		$sequence_2 = { 488b7d98 8b742440 8b542458 41bb00020000 4c8d0d4e23feff 448a3f 4584ff }
		$sequence_3 = { 7510 b810000000 488b5c2430 4883c420 5f c3 4885db }
		$sequence_4 = { 85ff 0f8513ffffff 33c0 4c8b642450 4c8b6c2458 488b5c2460 4883c430 }
		$sequence_5 = { 442b8486a0e10300 4533d8 83bf800000000a 0f863c010000 8b4730 8b4f70 458d0c03 }
		$sequence_6 = { 8bc3 483bd0 0f871a050000 4c8d151995fdff 4403f2 4b8b8ceaa0511100 8a443108 }
		$sequence_7 = { 8bfd 66895802 410fb78704100000 0fbfcb }
		$sequence_8 = { 7cda 440fbf4302 418bd4 488bce 468d048508000000 e8???????? 488d0d33240300 }
		$sequence_9 = { 48833d????????00 488d0581900300 740f 3908 740e 4883c010 4883780800 }

	condition:
		7 of them and filesize <2318336
}