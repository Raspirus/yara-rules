rule MALPEDIA_Win_Killav_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "1d5124ec-5245-51ca-8b54-4fbeb7c8a843"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.killav"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.killav_auto.yar#L1-L114"
		license_url = "N/A"
		logic_hash = "6bdcae63c9d790007a185fb309199c790674ed97c7a86b96314a377ad757753a"
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
		$sequence_0 = { c745e4e8e24200 e9???????? 894de0 c745e4e8e24200 e9???????? }
		$sequence_1 = { 8955e0 8b048d70ba4300 f644102801 747c }
		$sequence_2 = { 6a20 c745e000000000 e8???????? 8bf0 83c404 8975e0 }
		$sequence_3 = { 8b45f8 8b55f0 8b048570ba4300 807c022800 }
		$sequence_4 = { e8???????? 8b35???????? 6a00 6880000000 6a03 6a00 6a00 }
		$sequence_5 = { c645fc1c 50 8d4dd0 e8???????? c645fc00 8b55ec 83fa08 }
		$sequence_6 = { 8b049570ba4300 885c012e 8b049570ba4300 804c012d04 }
		$sequence_7 = { 8d45d8 c645fc37 50 8d4dd0 }
		$sequence_8 = { 6bf838 894df8 8b048d70ba4300 33c9 }
		$sequence_9 = { e8???????? 8d45d8 c645fc08 50 8d4dd0 }

	condition:
		7 of them and filesize <517120
}