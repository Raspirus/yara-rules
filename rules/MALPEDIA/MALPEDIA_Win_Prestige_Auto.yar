rule MALPEDIA_Win_Prestige_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "554de8b7-e6ad-5535-8c14-f95b90ec653d"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prestige"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.prestige_auto.yar#L1-L129"
		license_url = "N/A"
		logic_hash = "3d9139c6507e377e5a1b52cf299e6f205e8499ed341925da786360ebd802ec9b"
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
		$sequence_0 = { 894648 8b7a4c 897e4c 837a4c10 7706 }
		$sequence_1 = { 03f3 c706652b3030 8d4604 33d2 e9???????? 8bd1 c745c409000000 }
		$sequence_2 = { 83f826 7603 6a26 58 0fb60c85be534700 0fb63485bf534700 }
		$sequence_3 = { b9fe020000 3bc1 0f4fc1 8d8decfcffff 50 8985e8fcffff e8???????? }
		$sequence_4 = { 3bf0 730a 8bc6 89742410 897c2414 50 ff7508 }
		$sequence_5 = { 8d45fc 50 8bd6 e8???????? 8b7508 8bf8 59 }
		$sequence_6 = { 8bf2 57 8bf9 8d4e02 668b06 83c602 6685c0 }
		$sequence_7 = { 85c0 740c 8d432c 8945f8 8b00 }
		$sequence_8 = { 8945d8 8b45e8 5e 13ce f765e0 6a00 8945ec }
		$sequence_9 = { 59 c3 8b4c240c 68???????? e8???????? 8b44240c 5e }

	condition:
		7 of them and filesize <1518592
}