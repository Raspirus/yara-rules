rule MALPEDIA_Win_Dharma_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "e57e8a97-3ba4-55fc-8a7a-2d2cd02d04a4"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dharma"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.dharma_auto.yar#L1-L125"
		license_url = "N/A"
		logic_hash = "7cad44063f19785eb5f21218749fc586efdec21afeaf1b9147edb5d8331036bc"
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
		$sequence_0 = { 8945e8 8b45ec 8b4808 8b55ec }
		$sequence_1 = { 8b4824 8b5508 8b4218 8d0c48 51 68ff7f0000 }
		$sequence_2 = { 68???????? 6a00 6a00 e8???????? eb0e 8b4dfc 51 }
		$sequence_3 = { 8b45e4 034530 8945e4 8b4dfc 034d30 894dfc 6a06 }
		$sequence_4 = { a1???????? 898574ffffff 6880000000 68???????? 8b8d74ffffff 51 68???????? }
		$sequence_5 = { 8945fc 8b4d08 0fb711 d1fa 8955e0 8b45f8 c1e818 }
		$sequence_6 = { 741a 8b5508 83c22c 8b4dfc 8b8108000100 }
		$sequence_7 = { 8b0c85b8bf4000 81e10000ff00 33d1 8b45f4 }
		$sequence_8 = { d1f8 8d4c0002 51 e8???????? 83c404 8b55ec 8b4a08 }
		$sequence_9 = { 8b55f4 83c201 8955f4 eba3 8b45f8 50 e8???????? }

	condition:
		7 of them and filesize <204800
}