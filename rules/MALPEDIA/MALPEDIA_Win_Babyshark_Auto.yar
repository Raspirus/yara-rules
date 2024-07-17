rule MALPEDIA_Win_Babyshark_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "bba62dea-b8fb-5177-af59-ee7484609223"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.babyshark"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.babyshark_auto.yar#L1-L124"
		license_url = "N/A"
		logic_hash = "170a55c792dd841a430b5276e4b7ea8cd0c0e2d28c406b503a22728951bd6c1d"
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
		$sequence_0 = { 83c40c 8d4c2404 6a00 51 ffd6 6a00 }
		$sequence_1 = { 8bc8 83e01f c1f905 8b0c8d607e4000 8a44c104 83e040 }
		$sequence_2 = { 8b0c8d607e4000 8a44c104 83e040 c3 a1???????? }
		$sequence_3 = { bf???????? f3ab 8d3452 895dfc c1e604 aa 8d9ec8674000 }
		$sequence_4 = { 80e920 ebe0 80a0206c400000 40 3bc6 72be 5e }
		$sequence_5 = { 8db6bc674000 bf???????? a5 a5 59 a3???????? }
		$sequence_6 = { 8a8094504000 83e00f eb02 33c0 0fbe84c6b4504000 }
		$sequence_7 = { c1f804 83f807 8945d0 0f879a060000 ff2485271a4000 834df0ff }
		$sequence_8 = { 5e 8d0c8dc8614000 3bc1 7304 3910 7402 }
		$sequence_9 = { ff15???????? 8bf0 68???????? 8d442408 68???????? 50 }

	condition:
		7 of them and filesize <65272
}