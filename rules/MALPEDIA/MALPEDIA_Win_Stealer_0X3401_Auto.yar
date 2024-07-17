
rule MALPEDIA_Win_Stealer_0X3401_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "bb4f4861-3b94-5ae9-a941-991186118cf0"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stealer_0x3401"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.stealer_0x3401_auto.yar#L1-L122"
		license_url = "N/A"
		logic_hash = "5581efed5fdecbce8348574e847d7eb07ab8e38c2ac3e166eb58c72b5a5419d5"
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
		$sequence_0 = { 03f2 8bd6 85f6 7e37 8d8d5cfeffff e8???????? }
		$sequence_1 = { 53 e8???????? 83c41c c74424280f000000 c744242400000000 c644241400 803b00 }
		$sequence_2 = { 5f 894df0 8b34cd50fa0110 8b4d08 6a5a 2bce }
		$sequence_3 = { 83781410 7202 8b00 ffb57cfdffff }
		$sequence_4 = { c745fc05000000 8d8d5cffffff e8???????? c645fc06 83781410 7202 }
		$sequence_5 = { 8b8db87dffff 40 3d00100000 722a f6c11f }
		$sequence_6 = { 64a300000000 8b35???????? 8d8574ffffff 50 6a00 }
		$sequence_7 = { 8d8598feffff 3bc3 7435 8bc8 e8???????? }
		$sequence_8 = { 8d4c2434 e8???????? 53 e8???????? 83c404 8d44242c 8bcf }
		$sequence_9 = { ffb5843fffff ffd7 83bd803fffff00 0f84ec000000 6a12 68???????? b9???????? }

	condition:
		7 of them and filesize <357376
}