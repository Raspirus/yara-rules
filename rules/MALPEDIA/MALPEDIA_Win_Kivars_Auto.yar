rule MALPEDIA_Win_Kivars_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "81082c3d-5064-55a3-8cee-83fb88e85d6c"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kivars"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.kivars_auto.yar#L1-L170"
		license_url = "N/A"
		logic_hash = "57db268647853b0be399381edf4cd6dc1a86ac28f0c0a8c22aae4b45830a7fb0"
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
		$sequence_0 = { c705????????00000000 c644245423 c744245002000000 488d4c2450 e8???????? }
		$sequence_1 = { 8d542440 8944244c 894c243c 6a14 }
		$sequence_2 = { 8d8c247c010000 51 e8???????? 83c404 33c0 5f 5e }
		$sequence_3 = { 44894c2420 4c89442418 89542410 48894c2408 4881eca8000000 488b05???????? }
		$sequence_4 = { ff15???????? 8bc8 8d7308 83e908 8dbc2492000000 8bd1 }
		$sequence_5 = { 4889842470020000 ff15???????? 89842430020000 c784242002000001000000 c784242c02000002000000 c64424707d }
		$sequence_6 = { 755d 4c8b8424e0050000 488d942460020000 488d8c2450010000 e8???????? }
		$sequence_7 = { 4883c005 4889442428 488b842470100000 4883c009 }
		$sequence_8 = { 894c2430 89442444 894c2434 89442448 894c2438 8d542440 8944244c }
		$sequence_9 = { 488d942440010000 488d4c2430 e8???????? 8b442434 83e001 85c0 }
		$sequence_10 = { 50 8b4d18 51 8d5514 }
		$sequence_11 = { 7476 eb09 80fb3d 0f8489000000 0fbe5c2412 c0e202 8a5c1c14 }
		$sequence_12 = { 488bc8 ff15???????? 8b842460110000 ffc0 }
		$sequence_13 = { 83fffe 741b 83ffff 0f858c000000 8d8c247c010000 }
		$sequence_14 = { 8bf0 83c609 33ff 6a74 897c2414 e8???????? 83c404 }
		$sequence_15 = { 48894c2408 4881ec68030000 48c7842448030000feffffff 488d8c2430010000 e8???????? }

	condition:
		7 of them and filesize <196608
}