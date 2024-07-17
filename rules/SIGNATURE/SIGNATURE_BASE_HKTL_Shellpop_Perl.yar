rule SIGNATURE_BASE_HKTL_Shellpop_Perl : FILE
{
	meta:
		description = "Detects Shellpop Perl script"
		author = "Tobias Michalski"
		id = "d597d213-a70b-5412-adde-791b4d498848"
		date = "2018-05-18"
		modified = "2023-12-05"
		reference = "https://github.com/0x00-0x00/ShellPop"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4310-L4323"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8f3c5920acdc080b437c15b93e192a00a5037be0323cc04473e238033b7d53ec"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "32c3e287969398a070adaad9b819ee9228174c9cb318d230331d33cda51314eb"

	strings:
		$ = "perl -e 'use IO::Socket::INET;$|=1;my ($s,$r);" ascii
		$ = ";STDIN->fdopen(\\$c,r);$~->fdopen(\\$c,w);s" ascii

	condition:
		filesize <2KB and 1 of them
}