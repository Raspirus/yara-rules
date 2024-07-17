
rule SIGNATURE_BASE_WEBSHELL_PAS_Webshell_Perlnetworkscript : FILE
{
	meta:
		description = "Detects PERL scripts created by P.A.S. webshell"
		author = "FR/ANSSI/SDO"
		id = "1625b63f-ead7-5712-92b4-0ce6ecc49fd4"
		date = "2021-02-15"
		modified = "2024-05-25"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sandworm_centreon.yar#L44-L62"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b170c07a005e737c8069f2cc63f869d4d3ff6593b3bfca5bcaf02d7808da6852"
		score = 90
		quality = 85
		tags = "FILE"

	strings:
		$pl_start = "#!/usr/bin/perl\n$SIG{'CHLD'}='IGNORE'; use IO::Socket; use FileHandle;"
		$pl_status = "$o=\" [OK]\";$e=\" Error: \""
		$pl_socket = "socket(SOCKET, PF_INET, SOCK_STREAM,$tcp) or die print \"$l$e$!$l"
		$msg1 = "print \"$l OK! I\\'m successful connected.$l\""
		$msg2 = "print \"$l OK! I\\'m accept connection.$l\""

	condition:
		filesize <6000 and ($pl_start at 0 and all of ($pl*)) or any of ($msg*)
}