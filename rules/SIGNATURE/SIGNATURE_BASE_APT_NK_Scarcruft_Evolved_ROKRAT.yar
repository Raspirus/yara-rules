
rule SIGNATURE_BASE_APT_NK_Scarcruft_Evolved_ROKRAT : APT FILE
{
	meta:
		description = "Detects RokRAT malware used by ScarCruft APT group"
		author = "S2WLAB_TALON_JACK2"
		id = "53cabf41-0154-5372-b667-60d8a7cb9806"
		date = "2021-07-09"
		modified = "2023-12-05"
		reference = "https://medium.com/s2wlab/matryoshka-variant-of-rokrat-apt37-scarcruft-69774ea7bf48"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_nk_inkysquid.yar#L135-L179"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "01a2f410687c943d6c6e421ffacfe42f9e7b6afb82e43ba03a8d525e075a3a3c"
		score = 75
		quality = 85
		tags = "APT, FILE"
		type = "APT"
		version = "0.1"

	strings:
		$AES_IV_KEY = {
        C7 44 24 ?? 32 31 12 23
        C7 44 24 ?? 34 45 56 67
        C7 44 24 ?? 78 89 9A AB
        C7 44 24 ?? 0C BD CE DF
        C7 45 ?? 2B 7E A5 16
        C7 45 ?? 28 AE D2 A6
        C7 45 ?? AB F7 15 88
        C7 45 ?? 09 CF 4F 3C
        }
		$url_deocde = {
               80 E9 0F
               80 F1 C8
               88 48 ??
               48 83 EA 01  }

	condition:
		uint16(0)==0x5A4D and any of them
}