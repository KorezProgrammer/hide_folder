#include <iostream>
#include <filesystem>
#include <Windows.h>
#include <string>
#include <map>

using namespace std::filesystem;

std::map <char, std::string> encrypt;
std::vector <int> num;
HKEY hKey, perhkey;
LPCTSTR subKey = L"S-1-5-19\\Control Panel\\PowerCfg\\PowerPolicies\\SystemFile";
LPCTSTR persubkey = L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags\\SystemCode";
std::string passw, password, personal;
std::string max = std::to_string(password.max_size());
std::vector <int> mVector;
std::vector <int> nCode;
std::string newNum = "";
std::string perhash;
std::wstring perstringValue;
std::string resultCode = "";
WCHAR data[1024], perdata[1024];

void name();
bool isHidden(const std::wstring&);
bool IsRunAsAdmin();
bool doesKeyExist(const std::wstring&);
size_t hashfunc(const std::string&);
std::string chrand();
void analyzePassword(std::string&);
std::string encryptionPassword(std::string&);
void set_NationalCode_And_Password();
void decryption();
void set_Password();
std::string encryptionNationalCode(std::string);
class MyEncryption
{
public:
    std::string Encrypt(std::string& content);

    MyEncryption();

private:
    std::map<char, std::string> encrypt;
};

std::string MyEncryption::Encrypt(std::string& content)
{
    std::string encrypted_content = "";

    for (auto ch : content)
    {
        if (ch >= 32 && ch <= 122)
        {
            encrypted_content += encrypt[ch];
        }
        else
        {
            encrypted_content += ch;
        }
    }

    return encrypted_content;
}

int main(int argc, char const* argv[])
{
    srand(static_cast<unsigned int>(time(0)));
    //Cheeck run as adminstrator
    if (!IsRunAsAdmin())
    {
        SHELLEXECUTEINFO sei = { sizeof(SHELLEXECUTEINFO) };
        sei.lpVerb = L"runas";
        sei.lpFile = L"hide folder.exe";
        sei.nShow = SW_NORMAL;

        if (ShellExecuteEx(&sei) == ERROR_SUCCESS)
        {
            return 0;
        }
        else
        {
            return 1;
        }
    }
    
    DWORD type, pertype;
    DWORD dataSize = sizeof(data);
    DWORD perdataSize = sizeof(perdata);
    // Open registry key
    RegOpenKeyEx(HKEY_USERS, subKey, 0, KEY_READ, &hKey);
    RegOpenKeyEx(HKEY_CURRENT_USER, persubkey, 0, KEY_READ, &perhkey);
    // Get value data
    RegGetValue(hKey, NULL, L"System", RRF_RT_REG_SZ, &type, data, &dataSize);
    RegGetValue(perhkey, NULL, L"Code", RRF_RT_REG_SZ, &pertype, perdata, &perdataSize);
    // Close registry key
    RegCloseKey(hKey);
    RegCloseKey(perhkey);

    std::string addres = argv[0];
    size_t pos = addres.find_last_of("\\");
    addres = addres.erase(pos);
    std::vector <std::string> filen;
    int var;
    std::wstring foldern = L"C:\\Windows\\System32\\ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­  control.panel.{ED7BA470-8E54-465E-825C-99712043E01C}";

    //Get the contents
    for (auto &ad : directory_iterator(addres))
    {
        filen.push_back(ad.path().filename().string());
    }
    //Checking the existence of the folder
    for (var = 0; var < filen.size(); var++)
    {
        if ((filen[var] == "Hidden_folder_locked_by_cpp"))
        {
            break;
        }
    }
    //Check whether the folder is hidden  
    if (!isHidden(foldern))
    {
        //Checking the existece of the key in the registry
        if (!(doesKeyExist(subKey)))
        {
            create_directory("Hidden_folder_locked_by_cpp");
            name();
            set_NationalCode_And_Password();
        }
        else
        {
            if (var == filen.size())
            {
                name();
                std::cerr << "You can only have one hidden folder\nYou cannot change the password.\nDo you want to change your password? (y/n): ";
                while (true)
                {
                    getline(std::cin, personal);
                    if (personal == "y")
                    {
                        std::cout << "\nEnter 0 for exit.\nEnter your national code: ";
                        getline(std::cin, personal);
                        //Convert wchar to string and hashing national code
                        char ch[1024];
                        char defch = ' ';
                        WideCharToMultiByte(CP_ACP, 0, perdata, -1, ch, 1024, &defch, NULL);
                        std::string x = ch;
                        std::wstring personal2(x.begin(), x.end());
                        perhash = encryptionNationalCode(personal);
                        std::wstring perstringValue(perhash.begin(), perhash.end());
                        //check the national code
                        while (true)
                        {
                            if (personal == "0")
                            {
                                break;
                            }
                            else if (perstringValue == personal2)
                            {
                                //delete the password key
                                RegDeleteKey(HKEY_USERS, subKey);
                                std::cout << "\nOK. Now close the program and open it again. You can change the password";
                                break;
                            }
                            else
                            {
                                std::cerr << "\nDont valid your national code. Please enter code again: ";
                                getline(std::cin, personal);
                                perhash = encryptionNationalCode(personal);
                                std::wstring perstringValue(perhash.begin(), perhash.end());
                            }
                        }
                    }
                    else if (personal == "n")
                    {
                        std::cout << "Ok. Your password has not been changed";
                        break;
                    }
                    else
                    {
                        std::cerr << "You must choose y or n: ";
                        continue;
                    }
                    break;
                }
            }
            else
            {
                //hiding operation
                name();
                std::system("powershell.exe -Command \"Write-Host 'Please wait until the operation is finishing!!'\"");
                std::system("powershell.exe -Command \"Copy-Item 'Hidden_folder_locked_by_cpp' 'C:\\Windows\\System32' -Recurse\"");
                std::system("powershell.exe -Command \"Remove-Item 'Hidden_folder_locked_by_cpp' -Recurse -Force\"");
                std::system("ren \"C:\\Windows\\System32\\Hidden_folder_locked_by_cpp\" \" ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­  control.panel.{ED7BA470-8E54-465E-825C-99712043E01C}\"");
                std::system("attrib +h +s \"C:\\Windows\\System32\\ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­  control.panel.{ED7BA470-8E54-465E-825C-99712043E01C}\"");
                std::system("powershell.exe -Command \"Clear-Host\"");
                name();
                std::system("powershell.exe -Command \"Write-Host 'Your folder has been hidden.'\"");
            }
        }
    }
    else
    {
        //Checking the existece of the key in the registry
        if (doesKeyExist(subKey))
        {
            if (var == filen.size())
            {
                name();
                decryption();
            }
            else
            {
                name();
                std::cerr << "Error!!!";
            }
        }
        else
        {
            name();
            set_Password();
        }
    }
    std::cin.get();
}


MyEncryption::MyEncryption()
{
    encrypt = std::map<char, std::string>({
        {'0', ">Lp$]"},
        {'1', "HG&o"},
        {'2', "{py15"},
        {'3', "Tk7"},
        {'4', "rIn1@"},
        {'5', "mor4"},
        {'6', "=uT%"},
        {'7', "TGv"},
        {'8', "C1!w"},
        {'9', "_Ade"},
        {' ', "hejO"},
        {'!', "12_l"},
        {'\"', "@;a"},
        {'#', "l[po"},
        {'$', "L}0O"},
        {'%', "/0{}"},
        {'&', "Za2^"},
        {'\'', "+rEhi"},
        {'(', "-;kop"},
        {')', "2l"},
        {'*', "?pp]"},
        {'+', "mI;q"},
        {',', "XZs@9"},
        {'-', ":>BB"},
        {'.', "Edt%"},
        {'/', "|F%|"},
        {':', "me?"},
        {';', "<po0+>"},
        {'<', "pnCR"},
        {'=', "r+#"},
        {'>', "\\9gir"},
        {'?', "i99O"},
        {'@', "^Y?af3"},
        {'A', "/,kG"},
        {'B', "Winj"},
        {'C', "phun!"},
        {'D', "*4)("},
        {'E', "{+rnj}"},
        {'F', "Rc45"},
        {'G', ".LOp"},
        {'H', "ah+|"},
        {'I', "man5*"},
        {'J', "*(-0-)"},
        {'K', "pid12"},
        {'L', "Uj5)_"},
        {'M', "[[h<-q2"},
        {'N',"n@b/"},
        {'O', "0=0*0:"},
        {'P', "gs^8"},
        {'Q', "|A|"},
        {'R', "W:Lri"},
        {'S', "45+}{"},
        {'T', "Hol}"},
        {'U', "nar.,"},
        {'V', "?ko>?"},
        {'W', ";maj7"},
        {'X', "cAX:A"},
        {'Y', "$ZpL"},
        {'Z', ")hoR%"},
        {'[', "<=.S"},
        {'\\', ":+QG"},
        {']', "R_|/\\"},
        {'^', ",ki9"},
        {'_', "mnB#"},
        {'`', "*96ip"},
        {'a', "`s1T"},
        {'b', "fi8*"},
        {'c', ":rogi=6"},
        {'d', "caN !"},
        {'e', "bh6&/"},
        {'f', "abZZ>"},
        {'g', "mo+x\""},
        {'h', "rt<?"},
        {'i', "efZ,^L"},
        {'j', "baas?"},
        {'k', "ZXeA2"},
        {'l', "\'|vaq2%"},
        {'m', ">\"uj"},
        {'n', "rt2_O-0"},
        {'o', ";[_gi0"},
        {'p', ""},
        {'q', "m#5 8*"},
        {'r', "7!!=5040"},
        {'s', " jcr10)"},
        {'t', "uidW6"},
        {'u', "D477A@="},
        {'v', "~_G54{"},
        {'w', "$@EFs"},
        {'x', "="},
        {'y', "[i>uQ"},
        {'z', "Rae4)="},
        {'{', "@%aS,"},
        {'|', "arQ~_"},
        {'}', "\"aaaa\""},
        {'~', "\\/!zaL+"}
        });
}

void name()
{
    std::cout << "\n\n                                                    powered by\n\n" << "   ##             ##       ########           ###############       ###################   ########################\n   ##           ##       ##        ##         ##             ##     ##                                         ##\n   ##         ##       ##            ##       ##              ##    ##                                       ##\n   ##       ##       ##                ##     ##              ##    ##                                     ##\n   ##     ##        ##                  ##    ##              ##    ##                                   ##\n   ##   ##         ##                    ##   ##             ##     ##                                 ##\n   ## ##           ##                    ##   ###############       ###################              ##\n   ##   ##         ##                    ##   ## ##                 ##                             ##\n   ##     ##        ##                  ##    ##   ##               ##                           ##\n   ##       ##       ##                ##     ##     ##             ##                         ##\n   ##         ##       ##            ##       ##       ##           ##                       ##\n   ##           ##       ##        ##         ##         ##         ##                     ##\n   ##             ##       ########           ##           ##       ###################   #######################\n\n";
}

bool isHidden(const std::wstring& foldername)
{
    DWORD attributes = GetFileAttributesW(foldername.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES)
    {
        if (attributes & FILE_ATTRIBUTE_HIDDEN)
        {
            return true;
        }
    }
    return false;
}

bool IsRunAsAdmin()
{
    BOOL fIsRunAsAdmin = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PSID pAdministratorsGroup = NULL;

    // Allocate memory for SID of the Administrators group
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &pAdministratorsGroup))
    {
        dwError = GetLastError();
    }
    else
    {
        // Check whether the process is run with administrator privileges
        if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
        {
            dwError = GetLastError();
        }

        // Free SID allocated memory
        FreeSid(pAdministratorsGroup);
    }

    return (dwError == ERROR_SUCCESS && fIsRunAsAdmin);
}

bool doesKeyExist(const std::wstring& subKey)
{
    HKEY hKey;
    LONG result = RegOpenKeyEx(HKEY_USERS, subKey.c_str(), 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS)
    {

        RegCloseKey(hKey);
        return true;
    }
    else
    {
        // The key doesn't exist
        return false;
    }
}

size_t hashfunc(const std::string& str)
{
    std::hash<std::string> hasher;
    return hasher(str);
}

std::string chrand()
{
    int x;
    std::string ch = "";
    for (int i = 0; i < rand() % 10 + 10; i++)
    {
        x = rand() % 75 + 48;
        ch += (char)x;
    }
    return ch;
}

void analyzePassword(std::string& passw)
{
    bool num_control = 0;
    bool small_letter_control = 0;
    bool big_letter_control = 0;
    while (!big_letter_control)
    {
        bool check_space = 1;
        bool bigThan32 = 1;
        bool control = 0;
        if (passw.size() >= 8 && passw.size() <= 19)
        {
            for (int i = 0; i < passw.size(); i++)
            {
                if (!control)
                {
                    if ((num[i] == 8 && passw[i] == ' ') || (num[i] == 8 && passw[i] == '!') || (num[i] == 9 && passw[i] == ' ') || (num[i] == 9 && passw[i] == '!'))
                    {
                        std::cerr << "\nPlease put the space or \"!\" somewhere else.\nEnter a password again: ";
                        check_space = 0;
                        control = 1;
                        break;
                    }
                    if (passw[i] < 32)
                    {
                        std::cerr << "\nInvalid password.\nEnter a password again: ";
                        bigThan32 = 0;
                        control = 1;
                        break;
                    }
                }
            }
            if (check_space && bigThan32)
            {
                for (auto x : passw)
                {
                    if (!control)
                    {
                        if (x >= 48 && x <= 57)
                        {
                            num_control = 1;
                            break;
                        }
                        else
                        {
                            if (x == passw.back())
                            {
                                std::cout << "\nYou must enter at least one number.\nEnter a password again: ";
                                control = 1;
                            }
                        }
                    }
                }
            }
            if (num_control)
            {
                for (auto x : passw)
                {
                    if (!control)
                    {
                        if (x >= 97 && x <= 122)
                        {
                            small_letter_control = 1;
                            break;
                        }
                        else
                        {
                            if (x == passw.back())
                            {
                                std::cout << "\nYou must enter at least one lowercase letter.\nEnter a password again: ";
                                control = 1;
                            }
                        }
                    }
                }
            }
            if (small_letter_control)
            {
                for (auto x : passw)
                {
                    if (!control)
                    {
                        if (x >= 65 && x <= 90)
                        {
                            big_letter_control = 1;
                            break;
                        }
                        else
                        {
                            if (x == passw.back())
                            {
                                std::cout << "\nYou must enter at least one uppercase letter.\nEnter a password again: ";
                                control = 1;
                            }
                        }
                    }
                }
            }
            if (big_letter_control)
            {
                for (auto x : passw)
                {
                    if (!control)
                    {
                        if (x >= 32 && x <= 47)
                        {
                            break;
                        }
                    }
                }
            }
        }
        else
        {
            std::cout << "\nYour password must be between 8-19 digits.\nEnter a password again: ";
        }
        if (!big_letter_control)
        {
        getline(std::cin, passw);
        }
    }
}

std::string encryptionPassword(std::string& passw)
{
    for (int i = 0; i < passw.size(); i++)
    {
        if (passw[i] >= 32 && passw[i] <= 96)
        {
            passw[i] -= 24;
            passw[i] -= num[i];
        }
        else
        {
            passw[i] -= 32;
            passw[i] += num[i];
        }
    }
    passw += "!" + chrand();
    MyEncryption enc;
    std::string encrypt = enc.Encrypt(passw);
    return encrypt;
}

void set_NationalCode_And_Password()
{
    bool codeSize = 1;
    bool codeIsDigit = 1;
    bool flag = 1;
    int x = 0;
    std::cout << "You must enter at least one number.\n" << "You must enter at least one uppercase and lowercase letter.\n" << "Your password must be between 8-19 digits.\n" << "Choose a password for your hidden folder: ";
    getline(std::cin, passw);
    std::cout << "Enter your national Code: ";
    getline(std::cin, personal);
    while (1)
    {
        x = 0;
        if (personal.size() != 10)
        {
            codeSize = 0;
            std::cerr << "Your code must be 10 digits long.\nEnter code again: ";
            getline(std::cin, personal);
        }
        else
        {
            codeSize = 1;
        }
        for (int i = 0; i < personal.size(); i++)
        {
            if (personal[i] >= 48 && personal[i] <= 57)
            {
                x++;
            }
        }
        if (x==10)
        {
            codeIsDigit = 1;
            if (flag)
            {
                for (auto a : max)
                {
                    mVector.push_back(a - 48);
                }
                for (int i = 0; i < personal.size(); i++)
                {
                    nCode.push_back(personal[i] - 48);
                    mVector[i] += nCode[i];
                    newNum += std::to_string(mVector[i]);
                }
                for (int i = 10; i < max.size(); i++)
                {
                    newNum += max[i];
                }
                for (int i = 0; i < newNum.size(); i++)
                {
                    num.push_back(newNum[i] - 48);
                }
                analyzePassword(passw);
                flag = 0;
                //Creating key in Windows registry and write the password in there
                LONG result = RegCreateKeyEx(HKEY_USERS, subKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
                if (result == ERROR_SUCCESS)
                {
                    //Making the encryption algorithm (section2) {
                    passw = encryptionPassword(passw);
                    // }
                    std::wstring stringValue(passw.begin(), passw.end()); //Convert string to wstring
                    result = RegSetValueEx(hKey, L"System", 0, REG_SZ, reinterpret_cast<const BYTE*>(stringValue.c_str()), (stringValue.length() + 1) * sizeof(wchar_t));
                    if (result == ERROR_SUCCESS)
                    {
                        std::cout << "OK. The password selected.\n";
                    }
                    else
                    {
                        std::cerr << "Failed to set the password. Error code: " << result << "\n";
                    }
                }
                //Creating key in Windows registry and hashing national code and write the national code in the Windows registry
                LONG perresult = RegCreateKeyEx(HKEY_CURRENT_USER, persubkey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &perhkey, NULL);
                if (perresult == ERROR_SUCCESS)
                {
                    perhash = encryptionNationalCode(personal);
                    std::wstring perstringValue(perhash.begin(), perhash.end());
                    perresult = RegSetValueEx(perhkey, L"Code", 0, REG_SZ, reinterpret_cast<const BYTE*>(perstringValue.c_str()), (perstringValue.length() + 1) * sizeof(wchar_t));
                    if (perresult == ERROR_SUCCESS)
                    {
                        std::cout << "OK. The national code selected.\n";
                    }
                    else
                    {
                        std::cerr << "Failed to set the code. Error code: " << perresult << "\n";
                    }
                }
            }
        }
        else
        {
            codeIsDigit = 0;
            std::cout << "You only need to enter numbers.\nEnter code again: ";
            getline(std::cin, personal);
        }
        if (codeIsDigit && codeSize)
        {
            break;
        }
    }
}

void decryption()
{
    bool flag = true, flag2 = false;
    std::cout << "For exit enter 0\nEnter your national Code: ";
    //Convert wchar to string and hashed national code
    char ch[1024];
    char defch = ' ';
    WideCharToMultiByte(CP_ACP, 0, perdata, -1, ch, 1024, &defch, NULL);
    std::string x = ch;
    std::wstring personal2(x.begin(), x.end());
    while (1)
    {
        getline(std::cin, personal);
        if (personal == "0")
        {
            exit(0);
        }
        perhash = encryptionNationalCode(personal);
        std::wstring perstringValue(perhash.begin(), perhash.end());
        if (perstringValue == personal2)
        {
            std::cout << "\nOK. Enter password: ";
            getline(std::cin, password);
            if (password == "0")
            {
                exit(0);
            }
            for (auto a : max)
            {
                mVector.push_back(a - 48);
            }
            for (int i = 0; i < personal.size(); i++)
            {
                nCode.push_back(personal[i] - 48);
                mVector[i] += nCode[i];
                newNum += std::to_string(mVector[i]);
            }
            for (int i = 10; i < max.size(); i++)
            {
                newNum += max[i];
            }
            for (int i = 0; i < newNum.size(); i++)
            {
                num.push_back(newNum[i] - 48);
            }
            int correct_control = 0;
            //Convert wchar to string
            char ch[1024];
            char defch = ' ';
            WideCharToMultiByte(CP_ACP, 0, data, -1, ch, 1024, &defch, NULL);
            passw = ch;
            //decrypt operation            
            size_t del = passw.find_last_of("l");
            del -= 3;
            passw = passw.erase(del);
            password = encryptionPassword(password);
            password = password.erase(del);

            //Check the password        
            while (1)
            {
                if (password == "0")
                {
                    break;
                }
                else if (passw == password)
                {
                    //Disclosure operation
                    flag = false;
                    std::system("powershell.exe -Command \"Write-Host 'Please wait until the operation is finishing!!'\"");
                    std::system("attrib -h -s \"C:\\Windows\\System32\\ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­  control.panel.{ED7BA470-8E54-465E-825C-99712043E01C}\"");
                    std::system("ren \"C:\\Windows\\System32\\ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­  control.panel.{ED7BA470-8E54-465E-825C-99712043E01C}\" \"Hidden_folder_locked_by_cpp\"");
                    std::system("powershell.exe -Command \"Copy-Item 'C:\\Windows\\System32\\Hidden_folder_locked_by_cpp' '.\\' -Recurse\"");
                    std::system("powershell.exe -Command \"Remove-Item 'C:\\Windows\\System32\\Hidden_folder_locked_by_cpp' -Recurse -Force\"");
                    std::system("powershell.exe -Command \"Clear-Host\"");
                    name();
                    std::system("powershell.exe -Command \"Write-Host 'The password is correct.'\"");
                    std::system("powershell.exe -Command \"Write-Host 'The operation ended.'\"");
                    break;
                }
                else
                {
                    correct_control++;
                    if (flag)
                    {
                        if (correct_control == 3)
                        {
                            std::cout << "Did you forget your password? (y/n): ";
                            while (true)
                            {
                                getline(std::cin, personal);

                                if (personal == "y")
                                {
                                    std::cout << "\nEnter your national code: ";
                                    getline(std::cin, personal);
                                    //Convert wchar to string and hashed national code
                                    char ch[1024];
                                    char defch = ' ';
                                    WideCharToMultiByte(CP_ACP, 0, perdata, -1, ch, 1024, &defch, NULL);
                                    std::string x = ch;
                                    std::wstring personal2(x.begin(), x.end());
                                    perhash = encryptionNationalCode(personal);
                                    std::wstring perstringValue(perhash.begin(), perhash.end());
                                    //check national code
                                    while (true)
                                    {
                                        if (personal == "0")
                                        {
                                            exit(0);
                                        }
                                        else if (perstringValue == personal2)
                                        {
                                            RegDeleteKey(HKEY_USERS, subKey);
                                            flag = false;
                                            flag2 = true;
                                            std::cout << "\nOK. Now close the program and open it again. You can enter a new password\n";
                                            break;
                                        }
                                        else
                                        {
                                            std::cerr << "\nDont valid your national code. Please enter code again: ";
                                            getline(std::cin, personal);
                                            perhash = encryptionNationalCode(personal);
                                            std::wstring perstringValue(perhash.begin(), perhash.end());
                                        }
                                    }
                                }

                                else if (personal == "n")
                                {
                                    std::cout << "Ok. Your password has not been changed\n";
                                    break;
                                }
                                else
                                {
                                    std::cerr << "You must choose y or n: ";
                                    continue;
                                }
                                break;
                            }
                        }
                    }
                    if (flag)
                    {
                        std::cout << "Please enter your password again: ";
                        getline(std::cin, password);
                        if (password == "0")
                        {
                            exit(0);
                        }
                        password = encryptionPassword(password);
                        password = password.erase(del);
                    }
                }
                if (flag2)
                {
                    break;
                }
            }
            break;
        }
        else
        {
            std::cout << "Invalid code. \nPlease enter your national code: ";
        }
    }
}

void set_Password()
{
    bool flag = true, flag2 = false;
    std::cout << "For exit enter 0.\nEnter your national Code: ";
    getline(std::cin, personal);
    if (personal == "0")
    {
        exit(0);
    }
    while (1)
    {
        if (personal == "0")
        {
            exit(0);
        }
        //Convert wchar to string and hashed national code
        char ch[1024];
        char defch = ' ';
        WideCharToMultiByte(CP_ACP, 0, perdata, -1, ch, 1024, &defch, NULL);
        std::string x = ch;
        std::wstring personal2(x.begin(), x.end());
        perhash = encryptionNationalCode(personal);
        std::wstring perstringValue(perhash.begin(), perhash.end());
        if (perstringValue == personal2)
        {
            std::cout << "\nOK.\nYou must enter at least one number.\n" << "You must enter at least one uppercase and lowercase letter.\n" << "Your password must be between 8-19 digits.\n" << "Enter a new password for your hidden folder: ";
            getline(std::cin, passw);
            if (passw == "0")
            {
                exit(0);
            }
            for (auto a : max)
            {
                mVector.push_back(a - 48);
            }
            for (int i = 0; i < personal.size(); i++)
            {
                nCode.push_back(personal[i] - 48);
                mVector[i] += nCode[i];
                newNum += std::to_string(mVector[i]);
            }
            for (int i = 10; i < max.size(); i++)
            {
                newNum += max[i];
            }
            for (int i = 0; i < newNum.size(); i++)
            {
                num.push_back(newNum[i] - 48);
            }
            analyzePassword(passw);
            flag = 0;
            //Creating key in Windows registry and write the password in there
            LONG result = RegCreateKeyEx(HKEY_USERS, subKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
            if (result == ERROR_SUCCESS)
            {
                //Making the encryption algorithm (section2) {
                passw = encryptionPassword(passw);
                // }
                std::wstring stringValue(passw.begin(), passw.end());
                result = RegSetValueEx(hKey, L"System", 0, REG_SZ, reinterpret_cast<const BYTE*>(stringValue.c_str()), (stringValue.length() + 1) * sizeof(wchar_t));
                if (result == ERROR_SUCCESS)
                {
                    //Disclosure operation
                    std::system("powershell.exe -Command \"Write-Host 'Please wait until the operation is finishing!!'\"");
                    std::system("attrib -h -s \"C:\\Windows\\System32\\ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­  control.panel.{ED7BA470-8E54-465E-825C-99712043E01C}\"");
                    std::system("ren \"C:\\Windows\\System32\\ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­ ­  control.panel.{ED7BA470-8E54-465E-825C-99712043E01C}\" \"Hidden_folder_locked_by_cpp\"");
                    std::system("powershell.exe -Command \"Copy-Item 'C:\\Windows\\System32\\Hidden_folder_locked_by_cpp' '.\\' -Recurse\"");
                    std::system("powershell.exe -Command \"Remove-Item 'C:\\Windows\\System32\\Hidden_folder_locked_by_cpp' -Recurse -Force\"");
                    std::system("powershell.exe -Command \"Clear-Host\"");
                    name();
                    std::system("powershell.exe -Command \"Write-Host 'OK. set the new password.'\"");
                    std::system("powershell.exe -Command \"Write-Host 'The operation ended.'\"");
                    break;
                }
                else
                {
                    std::cerr << "Failed to set the password. Error code: " << result << "\n";
                }
            }
        }
        else
        {
            std::cout << "Invalid code. \nPlease enter your national code: ";
            getline(std::cin, personal);
        }
    }
}

std::string encryptionNationalCode(std::string code)
{
    resultCode = "";
    std::string codehash = std::to_string(hashfunc(code));
    for (int i = 0; i < codehash.size(); i++)
    {
        if (i == 0)
        {
            resultCode += std::to_string((codehash[i] - 48) * 3);
        }
        else if (i == 1)
        {
            if (codehash[i] == '0')
            {
                codehash[i] = '4';
            }
            resultCode += std::to_string((codehash[i] - 48) * 3);
        }
        else if (i == 2)
        {
            if (codehash[i] == '0')
            {
                codehash[i] = '6';
            }
            resultCode += std::to_string((codehash[i] - 48) * 5);
        }
        else if (i == 3)
        {
            if (codehash[i] == '0')
            {
                codehash[i] = '1';
            }
            resultCode += std::to_string((codehash[i] - 48) + 13);
        }
        else if (i == 4)
        {
            if (codehash[i] == '0')
            {
                codehash[i] = '7';
            }
            resultCode += std::to_string((codehash[i] - 48) * 7 - 4);
        }
        else if (i == 5)
        {
            if (codehash[i] == '0')
            {
                codehash[i] = '6';
            }
            resultCode += std::to_string((codehash[i] - 48) + 22);
        }
        else if (i == 6)
        {
            if (codehash[i] == '0')
            {
                codehash[i] = '1';
            }
            resultCode += std::to_string((codehash[i] - 48) + 2);
        }
        else if (i == 7)
        {
            resultCode += std::to_string((codehash[i] - 48) * 8);
        }
        else if (i == 8)
        {
            if (codehash[i] == '0')
            {
                codehash[i] = '2';
            }
            resultCode += std::to_string((codehash[i] - 48) * 5 - 1);
        }
        else if (i == 9)
        {
            if (codehash[i] == '0')
            {
                codehash[i] = '9';
            }
            resultCode += std::to_string((codehash[i] - 48) * 9 - 5);
        }
        else if (i == 10)
        {
            if (codehash[i] == '0')
            {
                codehash[i] = '4';
            }
            resultCode += std::to_string((codehash[i] - 48) * 13 / 6);
        }
        else if (i == codehash.size() - 1)
        {
            resultCode += std::to_string((codehash[i] - 48) * 10);
        }
        else
        {
            resultCode += codehash[i];
        }
    }
    return resultCode;
}