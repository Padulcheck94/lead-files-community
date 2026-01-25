#include "stdafx.h"
#include "locale_service.h"
#include "constants.h"
#include "banword.h"
#include "utils.h"
#include "mob_manager.h"
#include "empire_text_convert.h"
#include "config.h"
#include "skill_power.h"

using namespace std;

extern string		g_stQuestDir;
extern set<string> 	g_setQuestObjectDir;

string g_stServiceName;
string g_stServiceBasePath = ".";
string g_stServiceMapPath = "data/map";

string g_stLocale = "euckr";
string g_stLocaleFilename;

BYTE PK_PROTECT_LEVEL = 30;

string 			g_stLocal = "";
eLocalization 	g_eLocalType = LC_NOSET;

int (*check_name) (const char * str) = NULL;
int (*is_twobyte) (const char * str) = NULL;
bool LC_InitLocalization( const std::string& szLocal );

int is_twobyte_euckr(const char * str)
{
	return ishan(*str);
}

int is_twobyte_gb2312(const char * str)
{
	if (!str || !*str)
		return 0;

	BYTE b1 = str[0];
	BYTE b2 = str[1];

	if (!(b1 & 0x80))
		return 0;

	if (b1 < 0xb0 || b1 > 0xf7 || b2 < 0xa1 || b2 > 0xfe)
		return 0;

	return 1;
}

int is_twobyte_big5(const char * str)
{
	if (!str || !*str)
		return 0;

	BYTE b1 = str[0];
	BYTE b2 = str[1];
			
	BYTE b[2];

	b[0] = b2;
	b[1] = b1;
	
	WORD b12 = 0;
	memcpy(&b12, b, 2);

	if (!(b1 & 0x80))
		return 0;

	if ((b12 < 0xa440 || b12 > 0xc67e) && (b12 < 0xc940 || b12 > 0xf9d5))  
	{
		if (test_server)
		{
			sys_log(0, "twobyte_big5 %x %x", b1, b2);
		}
		return 0;
	}

	return 1;
}

int check_name_independent(const char * str)
{
	if (CBanwordManager::instance().CheckString(str, strlen(str)))
		return 0;

	// 몬스터 이름으로는 만들 수 없다.
	char szTmp[256];
	str_lower(str, szTmp, sizeof(szTmp));

	if (CMobManager::instance().Get(szTmp, false))
		return 0;

	return 1;
}

int check_name_gb2312(const char * str)
{
	static const BYTE exceptions[5][2] =
	{
		{ 0xd7, 0xfa },
		{ 0xd7, 0xfb },
		{ 0xd7, 0xfc },
		{ 0xd7, 0xfd },
		{ 0xd7, 0xfe }
	};

	int         i, j;
	BYTE        b1, b2;

	if (!str || !*str)
		return 0;

	i = 0;

	size_t len = 0;

	while (str[i])
	{
		if (str[i] & 0x80)
		{
			if (!str[i + 1])
				return 0;

			b1 = str[i++];
			b2 = str[i++];

			// 중국 간체는 첫번째 바이트 범위가 b0 -> f7 까지고
			// 두번째 바이트 범위가 a1 -> fe 다.
			if (b1 < 0xb0 || b1 > 0xf7 || b2 < 0xa1 || b2 > 0xfe)
				return 0;

			// 예외가 있다.
			for (j = 0; j < 5; j++)
				if (b1 == exceptions[j][0] && b2 == exceptions[j][1])
					return 0;

			len++;
		}
		else
		{
			if (!isdigit(str[i]) && !isalpha(str[i]))
				return 0;

			i++;
			len++;
		}
	}

	if ( len > 6 ) return 0;

	return check_name_independent(str);
}

int check_name_big5(const char * str )
{
	int i;
	BYTE b1, b2;

	if (!str || !*str)
		return 0;

	i = 0;

	while (str[i])
	{
		if (str[i] & 0x80)
		{
			if (!str[i + 1])
				return 0;

			b1 = str[i++];
			b2 = str[i++];

			BYTE b[2];

			b[0] = b2;
			b[1] = b1;

			// 중국 번체 ( big5 : 홍콩 )
			// 범위는 다음과 같다.
			//  big5: 0xA140--0xF9D5
			//  extended big5: 0x40--0x7E and 0xA1--0xFE

			// 0xa440-0xC67E
			// 0xC940-0xF9D5
			//
			/*	
				Plan Code Range Description 
				1 A140H - A3E0H Symbol and Chinese Control Code 
				1 A440H - C67EH Commonly Used Characters 
				2 C940H - F9D5H Less Commonly Used Characters 
				UDF FA40H - FEFE User-Defined Characters 

				8E40H - A0FEH User-Defined Characters 

				8140H - 8DFEH User-Defined Characters 

				8181H - 8C82H User-Defined Characters 

				F9D6H - F9F1H User-Defined Characters 
			*/

			WORD b12 = 0;
			memcpy(&b12, b, 2);

			if ((b12 < 0xa440 || b12 > 0xc67e) && (b12 < 0xc940 || b12 > 0xf9d5)) 
			{
				if (test_server)
					sys_log(0, "check_name_big5[%d][%s] %x %x %x", i - 2, str, b1, b2, b12);

				return 0;
			}
		}
		else
		{
			if (!isdigit(str[i]) && !isalpha(str[i]))
				return 0;

			i++;
		}
	}

	return check_name_independent(str);
}

int check_name_euckr(const char * str)
{
	int		code;
	const char*	tmp;

	if (!str || !*str)
		return 0;

	if ( strlen(str) < 2 || strlen(str) > 12 )
		return 0;

	for (tmp = str; *tmp; ++tmp)
	{
		// 한글이 아니고 빈칸이면 잘못된 것
		if (isnhspace(*tmp))
			return 0;

		// 한글이 아니고 숫자라면 적합하다.
		if (isnhdigit(*tmp))
			continue;

		// 한글이 아니고 영문이라면 적합하다.   
		if (!ishan(*tmp) && isalpha(*tmp))
			continue;

		code = *tmp;
		code += 256;

		if (code < 176 || code > 200)
			return 0;

		++tmp;

		if (!*tmp)
			break;
	}

	return check_name_independent(str);
}

int check_name_latin1(const char * str)
{
	int		code;
	const char*	tmp;

	if (!str || !*str)
		return 0;

	if (strlen(str) < 2)
		return 0;

	for (tmp = str; *tmp; ++tmp)
	{
		// 한글이 아니고 빈칸이면 잘못된 것
		if (isnhspace(*tmp))
			return 0;

		// 한글이 아니고 숫자라면 적합하다.
		if (isnhdigit(*tmp))
			continue;

		// 한글이 아니고 영문이라면 적합하다.   
		if (!ishan(*tmp) && isalpha(*tmp))
			continue;

		unsigned char uc_tmp = *tmp;

		if (uc_tmp == 145 || uc_tmp == 146 || uc_tmp == 196
				|| uc_tmp == 214 || uc_tmp == 220 || uc_tmp == 223 
				|| uc_tmp == 228 || uc_tmp == 246 || uc_tmp == 252 ) 
			continue;
		code = *tmp;
		code += 256;

		if (code < 176 || code > 200)
			return 0;

		++tmp;

		if (!*tmp)
			break;
	}

	return check_name_independent(str);
}

int check_name_alphabet(const char * str)
{
	const char*	tmp;

	if (!str || !*str)
		return 0;

	if (strlen(str) < 2)
		return 0;

	for (tmp = str; *tmp; ++tmp)
	{
		if (isdigit(*tmp) || isalpha(*tmp))
			continue;
		else
			return 0;
	}

	return check_name_independent(str);
}

void LocaleService_LoadLocaleStringFile()
{
	if (g_stLocaleFilename.empty())
		return;

	if (g_bAuthServer)
		return;

	fprintf(stderr, "LocaleService %s\n", g_stLocaleFilename.c_str());

	locale_init(g_stLocaleFilename.c_str());
}

void LocaleService_LoadEmpireTextConvertTables()
{
	char szFileName[256];

	for (int iEmpire = 1; iEmpire <= 3; ++iEmpire)
	{
		snprintf(szFileName, sizeof(szFileName), "%s/lang%d.cvt", LocaleService_GetBasePath().c_str(), iEmpire);
		sys_log(0, "Load %s", szFileName);

		LoadEmpireTextConvertTable(iEmpire, szFileName);
	}
}

static void __LocaleService_Init_DEFAULT()
{
	g_stLocaleFilename = "";

	g_stServiceBasePath = "locale/" + g_stServiceName;
	g_stServiceMapPath = g_stServiceBasePath + "/map";
	g_stQuestDir = g_stServiceBasePath + "/quest";

	g_setQuestObjectDir.clear();	
	g_setQuestObjectDir.insert(g_stQuestDir + "/object");
}

static void __CheckPlayerSlot(const std::string& service_name)
{
	if (PLAYER_PER_ACCOUNT != 4)
	{
		printf("<ERROR> PLAYER_PER_ACCOUNT = %d\n", PLAYER_PER_ACCOUNT);
		exit(0);
	}
}

bool LocaleService_Init(const std::string& c_rstServiceName)
{
	if (!g_stServiceName.empty())
	{
		sys_err("ALREADY exist service");
		return false;
	}

	g_stServiceName = c_rstServiceName;

	__LocaleService_Init_DEFAULT();

	fprintf(stdout, "Setting Locale \"%s\" (Path: %s)\n", g_stServiceName.c_str(), g_stServiceBasePath.c_str());

	__CheckPlayerSlot(g_stServiceName);

	if (false == LC_InitLocalization(c_rstServiceName))
		return false;
	
	return true;
}

void LocaleService_TransferDefaultSetting()
{
	if (!check_name)
		check_name = check_name_euckr;

	if (!is_twobyte)
		is_twobyte = is_twobyte_euckr;

	if (!exp_table)
		exp_table = exp_table_common;

	if (!CTableBySkill::instance().Check())
		exit(1);

	if (!aiPercentByDeltaLevForBoss)
		aiPercentByDeltaLevForBoss = aiPercentByDeltaLevForBoss_euckr;

	if (!aiPercentByDeltaLev)
		aiPercentByDeltaLev = aiPercentByDeltaLev_euckr;

	if (!aiChainLightningCountBySkillLevel)
		aiChainLightningCountBySkillLevel = aiChainLightningCountBySkillLevel_euckr;
}

const std::string& LocaleService_GetBasePath()
{
	return g_stServiceBasePath;
}

const std::string& LocaleService_GetMapPath()
{
	return g_stServiceMapPath;
}

const std::string& LocaleService_GetQuestPath()
{
	return g_stQuestDir;
}

bool LC_InitLocalization( const std::string& szLocal )
{
	g_stLocal = szLocal;

	return true;
}

eLocalization LC_GetLocalType() 
{
	return g_eLocalType;
}

bool LC_IsLocale( const eLocalization t ) 
{
	return LC_GetLocalType() == t ? true : false;
}

