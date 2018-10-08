#pragma once


// https://docs.microsoft.com/en-us/windows/desktop/secauthz/modifying-the-acls-of-an-object-in-c--
DWORD AddAceToObjectsSecurityDescriptor (
    LPTSTR pszObjName,          // name of object
    SE_OBJECT_TYPE ObjectType,  // type of object
    LPTSTR pszTrustee,          // trustee for new ACE
    TRUSTEE_FORM TrusteeForm,   // format of trustee structure
    DWORD dwAccessRights,       // access mask for new ACE
    ACCESS_MODE AccessMode,     // type of ACE
    DWORD dwInheritance         // inheritance flags for new ACE
);

CString GetWidowsErrorMessageByCode(DWORD errorMessageID);

DWORD GrantUserFullAccessToSharedFolder(CString username, CString path);

bool ModifyObjectRights(const CString useraccountname, const DWORD useraccount_type,
					   const DWORD permissions, const CString sharename,
					   CString* servername, const DWORD uses, DWORD Access, SE_OBJECT_TYPE ObjectType);

bool ShareModifyRights(const CString useraccountname, const DWORD useraccount_type,
					   const DWORD permissions, const CString sharename,
					   CString* servername, const DWORD uses, DWORD Access);

bool FolderModifyRights(const CString useraccountname, const DWORD useraccount_type,
					   const DWORD permissions, const CString sharename,
					   CString* servername, const DWORD uses, DWORD Access);

BOOL GetUserDomainName(CString *Name);