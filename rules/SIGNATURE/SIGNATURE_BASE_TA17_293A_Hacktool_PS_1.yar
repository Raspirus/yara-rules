rule SIGNATURE_BASE_TA17_293A_Hacktool_PS_1 : FILE
{
	meta:
		description = "Auto-generated rule"
		author = "Florian Roth (Nextron Systems)"
		id = "e4b92536-fa9a-5a65-8bd6-84c037dfbdce"
		date = "2017-10-21"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ta17_293A.yar#L152-L166"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a59834684cc1e7a34eeb8fb7f6cd1c414d6eab3ae58c6df763b2ec548705b371"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "72a28efb6e32e653b656ca32ccd44b3111145a695f6f6161965deebbdc437076"

	strings:
		$x1 = "$HashFormat = '$krb5tgs$23$*ID#124_DISTINGUISHED NAME: CN=fakesvc,OU=Service,OU=Accounts,OU=EnterpriseObjects,DC=asdf,DC=pd,DC=f" ascii
		$x2 = "} | Where-Object {$_.SamAccountName -notmatch 'krbtgt'} | Get-SPNTicket @GetSPNTicketArguments" fullword ascii

	condition:
		( filesize <80KB and 1 of them )
}