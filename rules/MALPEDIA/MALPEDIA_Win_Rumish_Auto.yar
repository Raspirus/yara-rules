rule MALPEDIA_Win_Rumish_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "c7d955e8-6589-5477-8769-7cb86586e6f1"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rumish"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.rumish_auto.yar#L1-L133"
		license_url = "N/A"
		logic_hash = "eaf86e8ce2c9b9b903be9f070aac683527bbc8f25626d1b33901e14e32dd278c"
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
		$sequence_0 = { 8d450c 50 e8???????? 8b4df8 e8???????? 8b45f8 8be5 }
		$sequence_1 = { eb46 68???????? 8d8d78feffff e8???????? eb34 68???????? 8d8d78feffff }
		$sequence_2 = { 7375 8b9570ffffff 0faf5580 039574ffffff 899574feffff 8d8574feffff 50 }
		$sequence_3 = { 898534ffffff 8b8d34ffffff 3b4d94 7d40 e8???????? 8985a8feffff }
		$sequence_4 = { 8d8df0faffff e8???????? e9???????? 68???????? 8d8df0faffff e8???????? e9???????? }
		$sequence_5 = { 0fbf4dbc 898d30ffffff 8b9530ffffff 83ea04 899530ffffff 83bd30ffffff0b 0f87a4020000 }
		$sequence_6 = { 7d5d e8???????? 898560ffffff db8560ffffff dc0d???????? dc35???????? d9bd5effffff }
		$sequence_7 = { e8???????? 6a01 8b55f0 52 8b4d9c 83c10c e8???????? }
		$sequence_8 = { 8bec 83ec08 894df8 51 8bcc 8965fc 8d450c }
		$sequence_9 = { 83e901 898d80feffff 8d9580feffff 52 8d4d84 e8???????? 8b4580 }

	condition:
		7 of them and filesize <770048
}