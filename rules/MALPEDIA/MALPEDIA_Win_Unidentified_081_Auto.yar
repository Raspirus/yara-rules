
rule MALPEDIA_Win_Unidentified_081_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "4bef4e35-3450-5f50-98ad-424279417112"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_081"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.unidentified_081_auto.yar#L1-L125"
		license_url = "N/A"
		logic_hash = "0bf113d92abe743278ae5a94b3d8f7a48f5ba7f91d2e79f1d3ac361b6c786f4e"
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
		$sequence_0 = { 8985c8fdffff 83f808 0f84ab090000 83f807 0f8777090000 ff24854fa44000 33c0 }
		$sequence_1 = { c74518f0944100 50 8d4dc4 e8???????? 68???????? 8d45c4 }
		$sequence_2 = { 68???????? b9???????? e8???????? c645fc03 33c0 }
		$sequence_3 = { eb02 33c0 8bbdc8fdffff 6bc009 0fb6bc38e8544100 8bc7 89bdc8fdffff }
		$sequence_4 = { 8b7508 c7465c48554100 83660800 33ff }
		$sequence_5 = { c645fc01 33c9 66a3???????? 66390d???????? 8bc6 c705????????07000000 0f44c1 }
		$sequence_6 = { 88440a34 8b049dd0d14100 c744023801000000 e9???????? ff15???????? 8bf8 }
		$sequence_7 = { 83e61f c1f805 c1e606 8b0485d0d14100 80643004fd 8b45f8 }
		$sequence_8 = { 6a01 6a00 f7d8 50 53 ff15???????? 8b8d34ffffff }
		$sequence_9 = { ff15???????? 837c241001 7507 b101 e8???????? 8b35???????? }

	condition:
		7 of them and filesize <273408
}