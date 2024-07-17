rule MALPEDIA_Win_Gup_Proxy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "5c3bfea3-920f-5316-9eb6-180474d2cca9"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gup_proxy"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.gup_proxy_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "d81f0061756179ec05e7cc548d81d0721d972a5a55f0d637cdd705d25b38ea90"
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
		$sequence_0 = { c744244400000000 c644243400 e8???????? c784242002000000000000 8d4c2444 6a00 }
		$sequence_1 = { c1e606 03348510974100 33db 395e08 }
		$sequence_2 = { 8b04bd10974100 830c06ff 33c0 eb16 e8???????? c70009000000 }
		$sequence_3 = { c1f805 c1e606 8b048510974100 80643004fd 8b45f8 8b55fc 5f }
		$sequence_4 = { c78588feffffc22eab48 50 8bce e8???????? 8bc3 889d88feffff c1e818 }
		$sequence_5 = { c3 b8???????? c705????????61984000 a3???????? c705????????f2984000 c705????????4c994000 c705????????d1994000 }
		$sequence_6 = { c784242002000000000000 8d4c2444 6a00 68???????? c74424600f000000 c744245c00000000 c644244c00 }
		$sequence_7 = { ebb4 c745e4d8a04100 a1???????? eb1a c745e4d4a04100 a1???????? }
		$sequence_8 = { ff15???????? 8b04bd10974100 830c06ff 33c0 }
		$sequence_9 = { 53 ff15???????? 83f8ff 752a 32c0 }

	condition:
		7 of them and filesize <247808
}