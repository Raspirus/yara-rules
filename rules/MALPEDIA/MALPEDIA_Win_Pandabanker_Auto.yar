rule MALPEDIA_Win_Pandabanker_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "58cad36d-92dc-5f57-8115-b38a95b1c2cd"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pandabanker"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.pandabanker_auto.yar#L1-L118"
		license_url = "N/A"
		logic_hash = "64182a4cfed301300c0a7df71a34e50b114a69353e8eb5e84fdb9f4804c83f2c"
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
		$sequence_0 = { 56 8bf2 57 83f8ff 7507 8bce e8???????? }
		$sequence_1 = { 57 8b4808 8d7c2418 8b4004 }
		$sequence_2 = { c1e202 8bfe 8bca 45 }
		$sequence_3 = { 7404 c6400109 8b442430 8bd5 014608 8bcf 56 }
		$sequence_4 = { eb2c 6a05 5a 8bcf }
		$sequence_5 = { c6007b 40 85db 7404 c6000a 40 c60000 }
		$sequence_6 = { e8???????? 8bf0 85f6 7411 8bcf }
		$sequence_7 = { 85ff 7423 8b0e 8bd5 }
		$sequence_8 = { e8???????? 8b742414 8bce 8b542418 89742424 e8???????? 84c0 }
		$sequence_9 = { 7508 33c0 85d2 0f95c0 c3 }

	condition:
		7 of them and filesize <417792
}