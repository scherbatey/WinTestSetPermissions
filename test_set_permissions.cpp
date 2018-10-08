// test_set_permissions.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "permissions.h"
#include <iostream>

int _tmain(int argc, _TCHAR* argv[])
{
	DWORD dwRes;
	CString UserDomain;
	GetUserDomainName(&UserDomain);
	std::cout << "Domain: " << UserDomain << std::endl;
	if (argc == 3) {
		//dwRes = GrantUserFullAccessToSharedFolder(argv[1], argv[2]);
		
		CString UserName;
		UserName = argv[1];

		std::cout << "Setting permissions for user: " << UserName << std::endl;

		const DWORD FULL_ACCESS_MASK = GENERIC_ALL;
		const DWORD SHI_USES_UNLIMITED = -1;

		dwRes = FolderModifyRights(UserName, TRUSTEE_IS_ALIAS, FULL_ACCESS_MASK, argv[2], NULL, SHI_USES_UNLIMITED, GRANT_ACCESS);
		if (!dwRes)
			std::cerr << "Error in FolderModifyRights!\n";

		dwRes = ShareModifyRights(UserName, TRUSTEE_IS_ALIAS, FULL_ACCESS_MASK, argv[2], NULL, SHI_USES_UNLIMITED, GRANT_ACCESS);

		if (!dwRes)
			std::cerr << "Error in ShareModifyRights!\n";
		//if (ERROR_SUCCESS != dwRes)
		//	std::cout << "ERROR: (" << dwRes << ") " << GetWidowsErrorMessageByCode(dwRes);
	}
	else
		dwRes = ~0UL;
	return dwRes;
}

