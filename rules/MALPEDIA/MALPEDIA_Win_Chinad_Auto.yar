rule MALPEDIA_Win_Chinad_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "55179322-c960-5946-aa14-87280de490d7"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chinad"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.chinad_auto.yar#L1-L130"
		license_url = "N/A"
		logic_hash = "f63725bd92056d22834dfb19b05368c2071df890649a72d3254d014778d263a0"
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
		$sequence_0 = { c7850cffffff00000000 eb55 c78550ffffffbc264300 8b9550ffffff 83c201 8995b4feffff 8b8550ffffff }
		$sequence_1 = { 8b85a8feffff 899485acfeffff e9???????? b904000000 6bd100 8b4508 8b0c10 }
		$sequence_2 = { 2bf8 8bc2 c1f819 03f0 897dec c1e019 }
		$sequence_3 = { 895de8 1bde 0145f4 8b75ac 119d7cffffff 8b5dec 81c300001000 }
		$sequence_4 = { 0fa4c119 c1ee07 c1e019 0bd1 0bf0 31b514fdffff }
		$sequence_5 = { 0fa4f701 6a13 03f6 03b55cffffff 89b560ffffff 137dcc 81c600000001 }
		$sequence_6 = { c1c802 33c8 8b85d4feffff 8bd8 03ca 2385d8feffff }
		$sequence_7 = { 81d7745dbe72 019d14fdffff 11bd38fdffff 33d2 0facc81c c1e604 }
		$sequence_8 = { 8b4e24 83c40c c1e903 b838000000 83e13f 83f938 7205 }
		$sequence_9 = { b894280000 e8???????? a1???????? 33c5 8945fc c78570d7ffff80280000 8d8570d7ffff }

	condition:
		7 of them and filesize <598016
}