
rule MALPEDIA_Win_Nestegg_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "01b2e0f8-b92c-591f-a2fe-591e7cf3b6b4"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nestegg"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.nestegg_auto.yar#L1-L121"
		license_url = "N/A"
		logic_hash = "d01d8400ee78b6e2d5585ed1b0eb91726b08169614c693b823bb545acd7b28b3"
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
		$sequence_0 = { e8???????? 8d5710 6a02 52 8bce e8???????? }
		$sequence_1 = { 83c40c 83feff 7417 ffd7 }
		$sequence_2 = { 8b0d???????? 81c120030000 51 ff15???????? 8b0d???????? 39991c030000 }
		$sequence_3 = { 83f80e 0f84d8000000 83f80f 7520 8d4c2430 56 }
		$sequence_4 = { 56 8bf1 89742404 c706???????? 8b8e24030000 c744241000000000 }
		$sequence_5 = { 85c9 740c 8a09 83e107 8d14c1 89542410 }
		$sequence_6 = { 8b10 6a10 51 8bc8 885c2458 ff5214 }
		$sequence_7 = { c644242f6e c644243065 c644243233 884c2433 885c2434 88542435 }
		$sequence_8 = { c644240d73 884c240e c644240f5f c644241033 }
		$sequence_9 = { e8???????? 8d4c2410 6a04 51 8bce c7442418ff020001 e8???????? }

	condition:
		7 of them and filesize <221184
}