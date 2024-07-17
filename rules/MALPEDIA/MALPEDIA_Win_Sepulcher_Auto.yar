rule MALPEDIA_Win_Sepulcher_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "666ccc80-c712-59f8-bf12-61bac5486b32"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sepulcher"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.sepulcher_auto.yar#L1-L124"
		license_url = "N/A"
		logic_hash = "fea20fdb29a4a6cc26bf9baf225a8110e30f06d577e665b386797a74632bb5da"
		score = 75
		quality = 73
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
		$sequence_0 = { 56 57 6a43 8bf9 58 6a4d 8db784480000 }
		$sequence_1 = { 7515 6a04 8d45bc 50 e8???????? 8b4db8 8bd0 }
		$sequence_2 = { 58 6a74 59 6a53 668945ea 58 }
		$sequence_3 = { 0fb71408 8bc2 c1e002 66393408 75f1 }
		$sequence_4 = { eb1a 8d45fc 50 8b04bd50de0110 ff743018 }
		$sequence_5 = { 668945d2 b8???????? 66894db4 66894dba 66894dc0 }
		$sequence_6 = { 56 57 6a5a 58 6a52 }
		$sequence_7 = { c1f906 6bd030 8b45fc 03148d50de0110 8b00 894218 }
		$sequence_8 = { 8bd8 895db0 8d0c4dffff0000 51 57 53 e8???????? }
		$sequence_9 = { 58 6a33 668945e8 668945ea 58 6a32 668945ec }

	condition:
		7 of them and filesize <279552
}