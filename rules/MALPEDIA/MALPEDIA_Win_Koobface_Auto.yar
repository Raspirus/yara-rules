rule MALPEDIA_Win_Koobface_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "1ce15537-cef6-5c0e-a9d8-b5edfbbc6020"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.koobface"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.koobface_auto.yar#L1-L128"
		license_url = "N/A"
		logic_hash = "b6b79af3be74d0a2238bfa51c4162b8333d68f5a5fb85b02563c06855a5cb17a"
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
		$sequence_0 = { 8d850cffffff 50 c745fc26000000 e8???????? 834dfcff 53 }
		$sequence_1 = { e8???????? 33db 59 889dfaf7ffff 889dfbf7ffff 899decf7ffff 899de0f7ffff }
		$sequence_2 = { 83bd34c1ffff0a 754c 8d8540c1ffff 6a41 50 }
		$sequence_3 = { 50 c745cc5cd74100 e8???????? 8b7508 bf63736de0 393e 0f85a5010000 }
		$sequence_4 = { e8???????? 50 8d8538f4ffff 50 e8???????? 8b8520f4ffff 59 }
		$sequence_5 = { e8???????? 8b8598faffff c1e803 50 8d85a4faffff 57 50 }
		$sequence_6 = { 8d8528ffffff 68???????? 50 e8???????? 83c40c 8d8528ffffff 50 }
		$sequence_7 = { 8d8528ffffff 50 e8???????? 68???????? 8d850857ffff }
		$sequence_8 = { 8d4de4 51 53 ff90e0000000 837de404 7407 }
		$sequence_9 = { 68???????? e8???????? 59 57 e8???????? 59 8b4dfc }

	condition:
		7 of them and filesize <368640
}