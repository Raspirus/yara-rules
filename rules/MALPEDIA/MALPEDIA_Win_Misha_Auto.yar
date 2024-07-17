
rule MALPEDIA_Win_Misha_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "3791b368-7721-59e9-a6c9-80386ca3e3f7"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.misha"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.misha_auto.yar#L1-L130"
		license_url = "N/A"
		logic_hash = "20e70ebbe7343afb7f42cf249a2a9fa16b58c61214c6be715dfea2d371ecbbbb"
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
		$sequence_0 = { 0fbe09 03c1 894510 8b45f8 40 8945f8 8b4510 }
		$sequence_1 = { c20400 55 8bec 51 837d0802 7448 837d0804 }
		$sequence_2 = { 8945dc 817d140000007e 7607 33c0 e9???????? 8b4524 }
		$sequence_3 = { 32c0 5d c3 56 8bf0 eb0a 8bce }
		$sequence_4 = { c78510ffffff04040404 c78514ffffff04040404 c78518ffffff04040404 c7851cffffff04040404 c78520ffffff05050505 c78524ffffff05050505 c78528ffffff05050505 }
		$sequence_5 = { 85c0 7404 2bf3 8930 b001 }
		$sequence_6 = { 8b450c 0590010000 50 e8???????? 83c414 b001 e9???????? }
		$sequence_7 = { 8b4dcc 8d440104 8945cc 837d900f 0f829e000000 837d1c00 741d }
		$sequence_8 = { 50 e8???????? 8b5508 56 6a1c 59 }
		$sequence_9 = { 8b4514 e8???????? 0fb64524 85c0 7456 6a00 68ffffff7f }

	condition:
		7 of them and filesize <710656
}