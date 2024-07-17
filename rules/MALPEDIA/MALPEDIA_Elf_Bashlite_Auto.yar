rule MALPEDIA_Elf_Bashlite_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "ca6414ba-2b9c-5f1f-bb06-5810c9d01c02"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.bashlite"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/elf.bashlite_auto.yar#L1-L113"
		license_url = "N/A"
		logic_hash = "38a010b68cee7bf4f221088e2245d1e5d0f927b085c409c35c3789c20373d434"
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
		$sequence_0 = { eb19 e8???????? c70016000000 e8???????? c70016000000 }
		$sequence_1 = { 21d0 3345fc c9 c3 55 }
		$sequence_2 = { 750c e8???????? 8b00 83f873 }
		$sequence_3 = { 8b85ecefffff c9 c3 55 }
		$sequence_4 = { 760f e8???????? c7001c000000 31c0 }
		$sequence_5 = { 31c0 eb19 e8???????? c70016000000 }
		$sequence_6 = { e8???????? 89c2 89d0 c1e81f 01d0 d1f8 }
		$sequence_7 = { 85c0 750c c785ecefffff01000000 eb0a c785ecefffff00000000 }
		$sequence_8 = { 85c0 750c c785ecefffff01000000 eb0a c785ecefffff00000000 8b85ecefffff }
		$sequence_9 = { c785ecefffff01000000 eb0a c785ecefffff00000000 8b85ecefffff c9 c3 }

	condition:
		7 of them and filesize <2310144
}