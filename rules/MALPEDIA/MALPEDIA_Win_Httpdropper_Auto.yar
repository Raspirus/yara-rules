
rule MALPEDIA_Win_Httpdropper_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "eb6cb470-4fa5-55f1-aaf4-34eabe7782e1"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.httpdropper"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.httpdropper_auto.yar#L1-L165"
		license_url = "N/A"
		logic_hash = "c6973c071283bf0dc986d288edaa8567196f172f5da7a23c655925f94d3c03cb"
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
		$sequence_0 = { 8d4c243c 51 8d54241c 52 53 }
		$sequence_1 = { 51 6a00 6a00 68???????? 52 c745f404000000 }
		$sequence_2 = { 7506 c60100 49 ebec 8bc3 }
		$sequence_3 = { e8???????? 6804010000 8d95edfdffff 6a00 52 c685ecfdffff00 }
		$sequence_4 = { 7414 57 c6470300 e8???????? 83c404 }
		$sequence_5 = { 51 8d95ecf8ffff 68???????? 52 e8???????? 8d85f4fdffff }
		$sequence_6 = { 6802000080 ff15???????? 8b85d8fbffff 8d8ddcfbffff 51 }
		$sequence_7 = { c685d4f4ffff00 e8???????? 57 68ff030000 }
		$sequence_8 = { 33c0 ba01000000 f2ae 448bc2 48f7d1 48ffc9 }
		$sequence_9 = { 48c7c102000080 4889442438 48897c2430 c74424283f000f00 897c2420 }
		$sequence_10 = { 33d2 41b804010000 c68424f000000000 e8???????? 488d15520f0200 488d8c24f0000000 }
		$sequence_11 = { 488bfb 488d73ff f2ae 48f7d1 48ffc9 }
		$sequence_12 = { 0fb7cd 4889442428 6689742428 4889442430 ff15???????? 488bcf }
		$sequence_13 = { e8???????? 488d8d81040000 33d2 41b87f0c0000 }
		$sequence_14 = { c1e808 418bd1 4032c7 4a0fbebc35da020000 81e2fdff0000 }
		$sequence_15 = { 488d4df0 e8???????? b801000000 e9???????? }

	condition:
		7 of them and filesize <524288
}