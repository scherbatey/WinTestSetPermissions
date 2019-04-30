#pragma once

#include "stdafx.h"
#include "permissions.h"

#include <Lm.h>
#include <iostream>
#include <LMShare.h>
#include <aclapi.h>

// https://docs.microsoft.com/en-us/windows/desktop/secauthz/modifying-the-acls-of-an-object-in-c--
DWORD AddAceToObjectsSecurityDescriptor (
    LPTSTR pszObjName,          // name of object
    SE_OBJECT_TYPE ObjectType,  // type of object
    LPTSTR pszTrustee,          // trustee for new ACE
    TRUSTEE_FORM TrusteeForm,   // format of trustee structure
    DWORD dwAccessRights,       // access mask for new ACE
    ACCESS_MODE AccessMode,     // type of ACE
    DWORD dwInheritance         // inheritance flags for new ACE
) 
{
    DWORD dwRes = 0;
    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS ea;

    if (NULL == pszObjName) 
        return ERROR_INVALID_PARAMETER;

    // Get a pointer to the existing DACL.

    dwRes = GetNamedSecurityInfo(pszObjName, ObjectType, 
          DACL_SECURITY_INFORMATION,
          NULL, NULL, &pOldDACL, NULL, &pSD);
    if (ERROR_SUCCESS != dwRes) {
        // printf( "GetNamedSecurityInfo Error %u\n", dwRes );
        goto Cleanup; 
    }  

    // Initialize an EXPLICIT_ACCESS structure for the new ACE. 

    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = dwAccessRights;
    ea.grfAccessMode = AccessMode;
    ea.grfInheritance= dwInheritance;
    ea.Trustee.TrusteeForm = TrusteeForm;
    ea.Trustee.ptstrName = pszTrustee;

    // Create a new ACL that merges the new ACE
    // into the existing DACL.

    dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
    if (ERROR_SUCCESS != dwRes)  {
        // printf( "SetEntriesInAcl Error %u\n", dwRes );
        goto Cleanup; 
    }  

    // Attach the new ACL as the object's DACL.

    dwRes = SetNamedSecurityInfo(pszObjName, ObjectType, 
          DACL_SECURITY_INFORMATION,
          NULL, NULL, pNewDACL, NULL);
    if (ERROR_SUCCESS != dwRes)  {
        // printf( "SetNamedSecurityInfo Error %u\n", dwRes );
        goto Cleanup; 
    }  

    Cleanup:

        if(pSD != NULL) 
            LocalFree((HLOCAL) pSD); 
        if(pNewDACL != NULL) 
            LocalFree((HLOCAL) pNewDACL); 

        return dwRes;
}


DWORD GrantUserFullAccessToSharedFolder(CString userName, CString path)
{
	DWORD dwRes = 0;

	dwRes = AddAceToObjectsSecurityDescriptor(
		path.GetBuffer(),
		SE_FILE_OBJECT,
		userName.GetBuffer(),
		TRUSTEE_IS_NAME,
		0x001F01FF,
		GRANT_ACCESS,
		SUB_CONTAINERS_AND_OBJECTS_INHERIT
	);

	if (ERROR_SUCCESS != dwRes)
		return dwRes;

	dwRes = AddAceToObjectsSecurityDescriptor(
		path.GetBuffer(),
		SE_LMSHARE,
		userName.GetBuffer(),
		TRUSTEE_IS_NAME,
		0x001F01FF,
		GRANT_ACCESS,
		SUB_CONTAINERS_AND_OBJECTS_INHERIT
	);

	return dwRes;
}

CString GetWidowsErrorMessageByCode(DWORD errorMessageID)
{
    //Get the error message, if any.
    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    CString message(messageBuffer, size);

    //Free the buffer.
    LocalFree(messageBuffer);

    return message;
}

bool ModifyObjectRights(const CString useraccountname, const DWORD useraccount_type,
					   const DWORD permissions, const CString sharename,
					   CString* servername, const DWORD uses, DWORD Access, SE_OBJECT_TYPE ObjectType)
{
	bool b_ret = false;

	PACL					pACL = NULL;
	PACL					pNewDACL = NULL;
	BOOL					bDacldef = SE_DACL_DEFAULTED;
	DWORD					dwRes =	3735936685;
	PSECURITY_DESCRIPTOR	pSecdes = NULL;
	PSHARE_INFO_502			pshare_info = NULL;
	wchar_t*				lpszserver = NULL;
	TCHAR*					lpszUserName = NULL;


	if(servername != NULL)
	{
		int nLength = servername->GetLength();
		lpszserver = new wchar_t[nLength+1];
		mbstowcs(lpszserver, servername->GetBuffer(nLength), nLength+1);
	}

	TCHAR* lpszShare = new TCHAR[sharename.GetLength()*sizeof(TCHAR)+sizeof(TCHAR)];
	_tcscpy(lpszShare, sharename.operator LPCTSTR());	
	// on accède au partage
	if(GetNamedSecurityInfo(lpszShare, ObjectType, DACL_SECURITY_INFORMATION, NULL, NULL, &pACL, NULL, &pSecdes) == ERROR_SUCCESS)
	{
		lpszUserName = new TCHAR[useraccountname.GetLength()*sizeof(TCHAR)+sizeof(TCHAR)];
		_tcscpy(lpszUserName, useraccountname.operator LPCTSTR());

		// mise a zero de la mémoire à utiliser
		EXPLICIT_ACCESS eaAccess;
		ZeroMemory(&eaAccess, sizeof(EXPLICIT_ACCESS));

		BuildExplicitAccessWithName(&eaAccess, lpszUserName, permissions, (ACCESS_MODE)Access, CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | SUB_CONTAINERS_AND_OBJECTS_INHERIT);
		eaAccess.Trustee.TrusteeType = (TRUSTEE_TYPE)useraccount_type; // passage d'un alias (equivaut à groupe)
		
		// ajout de l'entrée dans une nouvelle liste
		dwRes = SetEntriesInAcl(1, &eaAccess, pACL, &pNewDACL);
		if (ERROR_SUCCESS == dwRes)  
		{
			// ecriture des droits dans l'objet memoire share
			dwRes=SetNamedSecurityInfo(lpszShare, ObjectType, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL);
			b_ret = (dwRes == 0);
		}
		else
		{	
			b_ret=false;
		}
	}
//cleanup:

	if (lpszUserName != NULL)
		delete[] lpszUserName;

	if(pNewDACL != NULL) 
		LocalFree((HLOCAL) pNewDACL); 

	if(pSecdes!=NULL)
		LocalFree((HLOCAL) pSecdes); 

	if(lpszserver!=NULL)
		delete [] lpszserver;

	if(lpszShare!=NULL)
		delete[] lpszShare;

	return b_ret;
}

bool ShareModifyRights(const CString useraccountname, const DWORD useraccount_type,
					   const DWORD permissions, const CString sharename,
					   CString* servername, const DWORD uses, DWORD Access)
{
	return ModifyObjectRights(useraccountname, useraccount_type, permissions, sharename, servername, uses, Access, SE_LMSHARE);
}

bool FolderModifyRights(const CString useraccountname, const DWORD useraccount_type,
					   const DWORD permissions, const CString sharename,
					   CString* servername, const DWORD uses, DWORD Access)
{
	return ModifyObjectRights(useraccountname, useraccount_type, permissions, sharename, servername, uses, Access, SE_FILE_OBJECT);
}

BOOL GetUserDomainName(CString *Name)
{
	BOOL b_ret=FALSE;
	HANDLE						hProcess, hAccessToken;
	DWORD						dwInfoBufferSize;
	SID_IDENTIFIER_AUTHORITY	siaNTAuthority=SECURITY_NT_AUTHORITY;
	SID_NAME_USE				nameuse=SidTypeUser;
	DWORD						lname=2048,ldomain=2048;
	CString						name,domain;
	CHAR						b_name[2048],b_domain[2048];
	union	tokenbuffer
	{
		char var[2048];
		TOKEN_USER tok_user;
	} var_token;
	//on recupère les infos du process en cours
	hProcess=GetCurrentProcess();
	if(!OpenProcessToken(hProcess, TOKEN_READ, &hAccessToken))
		return FALSE;

	// recupération des informations sur l'utilisateur
	b_ret=GetTokenInformation(hAccessToken, TokenUser, var_token.var,2048, &dwInfoBufferSize);
	CloseHandle(hAccessToken);

	b_ret=IsValidSid((PSID)var_token.tok_user.User .Sid);
	//rercherche des nom d'utilisateurs et de domaine
	// on commence par la machine locale
	b_ret=LookupAccountSid(NULL,(PSID)var_token.tok_user.User .Sid,b_name,&lname,b_domain,&ldomain,&nameuse);
	if((b_ret)&&(Name!=NULL))
	{
		// retour du nom de domaine trouvé
		*Name=b_domain;
	}

	return b_ret;
}

#pragma comment(lib, "Netapi32.lib")
bool ShareNameDir(const CString& Name, const CString& SharePathName, const CString& ShareComment)
{
	// pour passage des chaines en unicode
	CStringW wShareName = Name;
	CStringW wSharePathName = SharePathName;
	CStringW wShareComment = ShareComment;

	SHARE_INFO_2 Buf;
	::ZeroMemory(&Buf, sizeof(SHARE_INFO_2));

	Buf.shi2_netname = (LPWSTR)wShareName.GetBuffer();
	Buf.shi2_type = STYPE_DISKTREE;
	Buf.shi2_remark = (LPWSTR)wShareComment.GetBuffer();
	Buf.shi2_permissions = ACCESS_ALL;
	Buf.shi2_max_uses = SHI_USES_UNLIMITED;
	Buf.shi2_current_uses = 1;
	Buf.shi2_path = (LPWSTR)wSharePathName.GetBuffer();
	Buf.shi2_passwd = NULL; // No password

	DWORD dwerr = 9999;
	NET_API_STATUS res=NetShareAdd (NULL, 2, (LPBYTE)&Buf, &dwerr);

	if (res!=NERR_Success)
	{
		CString osMsg;
		osMsg.Format(_T("ShareNameDir failed - Error %d (%x).\r\n\tName: %s\r\n\tSharePath: %s"), res, dwerr, (LPCTSTR)Name, (LPCTSTR)SharePathName);
		std::cout << osMsg << std::endl;

		return false;
	}

	return true;
}
