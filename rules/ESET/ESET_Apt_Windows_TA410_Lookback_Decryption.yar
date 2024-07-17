rule ESET_Apt_Windows_TA410_Lookback_Decryption : FILE
{
	meta:
		description = "Matches encryption/decryption function used by LookBack."
		author = "ESET Research"
		id = "91947c6b-f357-5cf8-8522-4dcd517d01cb"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/ta410/ta410.yar#L189-L254"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "016dca6be654fcd193acc481e6a998efbb77e7ebd09b26614422be1136dd02c0"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$initialize = {
            8B C6           //mov eax, esi
            99              //cdq
            83 E2 03        //and edx, 3
            03 C2           //add eax, edx
            C1 F8 02        //sar eax, 2
            8A C8           //mov cl, al
            02 C0           //add al, al
            02 C8           //add cl, al
            88 4C 34 10         //mov byte ptr [esp + esi + 0x10], cl
            46              //inc esi
            81 FE 00 01 00 00       //cmp esi, 0x100
            72 ??
        }
		$generate = {
            8A 94 1C 10 01 ?? ??    //mov dl, byte ptr [esp + ebx + 0x110]
            8D 8C 24 10 01 ?? ??    //lea ecx, [esp + 0x110]
            0F B6 C3        //movzx eax, bl
            0F B6 44 04 10      //movzx eax, byte ptr [esp + eax + 0x10]
            32 C2           //xor al, dl
            02 F0           //add dh, al
            0F B6 C6        //movzx eax, dh
            03 C8           //add ecx, eax
            0F B6 01        //movzx eax, byte ptr [ecx]
            88 84 1C 10 01 ?? ??    //mov byte ptr [esp + ebx + 0x110], al
            43              //inc ebx
            88 11           //mov byte ptr [ecx], dl
            81 FB 00 06 00 00       //cmp ebx, 0x600
            72 ??           //jb 0x10025930
        }
		$decrypt = {
            0F B6 C6        //movzx eax, dh
            8D 8C 24 10 01 ?? ??    //lea ecx, [esp + 0x110]
            03 C8           //add ecx, eax
            8A 19           //mov bl, byte ptr [ecx]
            8A C3           //mov al, bl
            02 C6           //add al, dh
            FE C6           //inc dh
            02 F8           //add bh, al
            0F B6 C7        //movzx eax, bh
            8A 94 04 10 01 ?? ??    //mov dl, byte ptr [esp + eax + 0x110]
            88 9C 04 10 01 ?? ??    //mov byte ptr [esp + eax + 0x110], bl
            88 11           //mov byte ptr [ecx], dl
            0F B6 C2        //movzx eax, dl
            0F B6 CB        //movzx ecx, bl
            33 C8           //xor ecx, eax
            8A 84 0C 10 01 ?? ??    //mov al, byte ptr [esp + ecx + 0x110]
            30 04 2E        //xor byte ptr [esi + ebp], al
            46              //inc esi
            3B F7           //cmp esi, edi
            7C ??           //jl 0x10025980
        }

	condition:
		uint16(0)==0x5a4d and all of them
}