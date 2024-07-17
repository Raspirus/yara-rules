
rule MALPEDIA_Win_Revenant_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a1374c5f-49ed-5419-afea-48c7289282d4"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.revenant"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.revenant_auto.yar#L1-L117"
		license_url = "N/A"
		logic_hash = "c5089ea5b4a1f250ceb154edb995f0fd96a084eb423c884f131dc135f20dbca0"
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
		$sequence_0 = { 4c8d4c2458 4889f1 4889c3 31c0 4889442420 4889da ff15???????? }
		$sequence_1 = { 4c89e1 e8???????? 488906 31c0 48894608 }
		$sequence_2 = { ba28000000 b940000000 ffd6 31d2 }
		$sequence_3 = { eb3a 4c89e1 e8???????? 488906 31c0 }
		$sequence_4 = { 4889442450 e8???????? 85c0 4189c7 }
		$sequence_5 = { 4c01c2 31c9 49f7d0 48ffc9 4939c8 740a 448a140a }
		$sequence_6 = { 41b842000000 4c89e1 ff15???????? 8b4c246c 4989c4 }
		$sequence_7 = { 8b00 41390424 7592 41c744240801000000 }
		$sequence_8 = { 4883c328 4839fb 7427 41b808000000 4889f2 4889d9 }
		$sequence_9 = { e8???????? ba04010000 b940000000 48c744242804010000 41ffd6 4885c0 }

	condition:
		7 of them and filesize <99328
}