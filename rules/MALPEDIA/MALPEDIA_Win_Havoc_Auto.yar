rule MALPEDIA_Win_Havoc_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "effddaaf-e7fe-58ad-88f4-e26f6d7794a2"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.havoc"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.havoc_auto.yar#L1-L121"
		license_url = "N/A"
		logic_hash = "dea553016c43a89176918937bfc9793358dadd2541e82f3880161a16c9ccfd07"
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
		$sequence_0 = { 85c0 7856 488b842488000000 488bb42488000000 4531c9 }
		$sequence_1 = { 48898424ae000000 4c8d442458 ba2a040000 8b842498000000 4889442448 }
		$sequence_2 = { 4488440101 448a440202 4488440102 448a440203 4488440103 4883c004 4883f820 }
		$sequence_3 = { 4885c0 7504 31f6 eb08 488b4030 ffc3 }
		$sequence_4 = { 55 4c89c5 57 56 4889d6 53 }
		$sequence_5 = { 4883ec28 488b410c 488b4904 488d5008 488b05???????? }
		$sequence_6 = { 488d4b10 4c8d4c2460 4889442460 8b442478 ba00000002 4c8d842490000000 }
		$sequence_7 = { f3a5 488bbc2480000000 488b742460 b934010000 f3a5 }
		$sequence_8 = { baff010f00 c744244001000000 4889442444 31c0 85f6 }
		$sequence_9 = { 4155 4154 4531e4 55 57 56 53 }

	condition:
		7 of them and filesize <164864
}