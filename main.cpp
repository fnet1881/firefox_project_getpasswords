#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sqlite3.h>
#include <filesystem>
#include <windows.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

using std::cout;
using std::cin;
using std::wcout;
using std::wcin;
using std::endl;
using std::getline;
using std::string;
using std::wstring;
using std::vector;
using std::ifstream;
using std::ofstream;
using std::filesystem::path;
using std::filesystem::directory_iterator;
using std::filesystem::exists;

//TODO
//fix O2 in repeatable data
//console wstring (in file norm)
//hashcat masterpass if exists
//others outputs of result? (telegram, mail ...)
//in old profiles other methods of keep db. 

int verbose = 0;
string path_DB = R"(C:\Users\0_0\Desktop\key4.db)";
string path_logins = R"(C:\Users\0_0\Desktop\logins.json)";
struct DataBase
{
    DataBase(const char* path, int read_flag)\
        : path(path), read_mode(read_flag), db(nullptr), stmt(nullptr){
        if (sqlite3_open_v2(path, &db, read_mode, 0) != SQLITE_OK){
            //cout << "open failed: " << sqlite3_errmsg(db) << endl;
            error = 1;
        }
    }
    ~DataBase(){
        if (stmt) 
            sqlite3_finalize(stmt);
        if (db) 
            sqlite3_close(db);
    }
    void prepare(const char* sql){
        if (stmt)
            sqlite3_finalize(stmt); stmt = nullptr;


        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) 
            error = 1;
    }
    int step(){
        return sqlite3_step(stmt);
    }
    const void* column_blob(){
        return sqlite3_column_blob(stmt, 0); 
    }
    int column_bytes(){
        return sqlite3_column_bytes(stmt, 0); 
    }
    int has_error(){ 
        return error; 
    }

private:
    string path;
    int read_mode;
    sqlite3* db;
    sqlite3_stmt* stmt;
    int error = 0;
};
struct PBES2
{
    string entry_salt;
    int iterations = 0;
    int keylen = 0;
    string iv;
    string cipher_text;

};
struct NSS
{
    operator PBES2() const{
        PBES2 p;
        p.iv = iv;
        p.cipher_text = cipher_text;
        return p;
    }
    string iv;
    string cipher_text;
};
struct LoginsPasswords
{
    string hostname;
    string username;
    string password;
};

int set_PBES2(string obj, PBES2& stru){
    if (obj.size() != 132 && obj.size() != 164) return 1;
    //PBES2
        //   30 LL        SEQUENCE
        //     30 LL      SEQUENCE
        //       06 09 OID PBES2
        //       30 LL    SEQUENCE
        //         30 LL  SEQUENCE
        //           06 09 OID PBKDF2
        //           30 LL SEQUENCE
        //             04 20 <entry_salt 32>
        //             02 01 <iterations>
        //             02 01 <keylen>
        //         30 LL  SEQUENCE (cipher)
        //           06 09 OID
        //           04 0e <IV 14>
        //     04 LL      OCTET STRING ciphertext

    int i = 0, len, i_ofsset;
    i = 0;
    //cout << obj.size() << endl;
    
    //SEQUENCE 30 81 a1
    i += 1; 
    if ((unsigned char)obj[i] == 0x81) i += 2;
    else if ((unsigned char)obj[i] == 0x82) i += 3;
    else i += 1;

    i += 2; 
    len = (unsigned char)obj[i - 1];//SEQUENCE
    i += 2; 
    len = (unsigned char)obj[i - 1]; 
    i += len;//OI
    i += 2; 
    len = (unsigned char)obj[i - 1];//SEQUENCE
    i += 2; 
    len = (unsigned char)obj[i - 1];//SEQUENCE
    i += 2; 
    len = (unsigned char)obj[i - 1]; 
    i += len;//OI
    i += 2; 
    len = (unsigned char)obj[i - 1];//SEQUENCE

    //a11_entry_salt
    i += 2; 
    len = (unsigned char)obj[i - 1]; 
    i_ofsset = i;
    stru.entry_salt = obj.substr(i_ofsset, len);
    i += len;

    //A F
    //x = 0
    //x = 0 * 16 + 10 = 10
    //x = 10 * 16 + 15 = 175
    //a11_iterations
    i += 2; 
    len = (unsigned char)obj[i - 1]; 
    i_ofsset = i;
    for (int k = 0; k < len; k++)
        stru.iterations = (stru.iterations * 256) + (unsigned char)obj[i_ofsset + k];
    i += len;

    //a11_keylen
    i += 2; 
    len = (unsigned char)obj[i - 1]; 
    i_ofsset = i;
    for (int k = 0; k < len; k++)
        stru.keylen = (stru.keylen * 256) + (unsigned char)obj[i_ofsset + k];
    i += len;

    //SEQUENCE
    i += 2; 
    len = (unsigned char)obj[i - 1]; 
    i += len;

    //SEQUENCE cipher
    i += 2; 
    len = (unsigned char)obj[i - 1];

    //OI AES
    i += 2; 
    len = (unsigned char)obj[i - 1]; 
    i += len;

    //a11_IV
    i += 2;
    len = (unsigned char)obj[i - 1];
    i_ofsset = i;
    stru.iv += (char)0x04;
    stru.iv += (char)len;
    stru.iv += obj.substr(i_ofsset, len);
    i += len;

    // a11_ciphertext
    i += 2; 
    len = (unsigned char)obj[i - 1]; 
    i_ofsset = i;
    stru.cipher_text = obj.substr(i_ofsset, len);
    return 0;
}
void set_NSS(string obj, NSS& stru){
    //   30 53                  SEQUENCE
    //   04 10                  OCTET STRING
    //     00..01               keyid
    //   30 1d                  SEQUENCE
    //     06 09                OID
    //       60 86 48 01 65 03 04 01 2a    OID AES-256-CBC 
    //     04 10                OCTET STRING
    //       6e 20 ab 8c ...    IV
    //   04 20                  OCTET STRING
    //     00 0a db dc ...      ciphertext


    int j = 0, j_len, j_ofsset;
    // SEQUENCE (верхняя)
    j += 1;
    if ((unsigned char)obj[j] == 0x81) j += 2;
    else if ((unsigned char)obj[j] == 0x82) j += 3;
    else j += 1;

    //keyid
    j += 2;
    j_len = (unsigned char)obj[j - 1];
    j += j_len;

    //SEQUENCE
    j += 2;
    j_len = (unsigned char)obj[j - 1];

    //OI AES
    j += 2;
    j_len = (unsigned char)obj[j - 1];
    j += j_len;

    //IV
    j += 2;
    j_len = (unsigned char)obj[j - 1];
    j_ofsset = j;
    stru.iv = obj.substr(j_ofsset, j_len);
    j += j_len;

    //ciphertext
    j += 2;
    j_len = (unsigned char)obj[j - 1];
    j_ofsset = j;
    stru.cipher_text = obj.substr(j_ofsset, j_len);
}
int aes_decrypt(PBES2 stru, string key, string& res){
    string aes_key = res;
    int len1 = 0, len2 = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (const unsigned char*)key.data(), \
        (const unsigned char*)stru.iv.data());
    EVP_DecryptUpdate(ctx, (unsigned char*)aes_key.data(), &len1,\
        (const unsigned char*)stru.cipher_text.data(), stru.cipher_text.size());
    int rc = EVP_DecryptFinal_ex(ctx, (unsigned char*)aes_key.data() + len1, &len2);
    EVP_CIPHER_CTX_free(ctx);

    if (rc != 1){
        return 1;
    }
    aes_key.resize(len1 + len2);
    res = aes_key;
    return 0;
}
int get_plain_data(string encrypted_info, string aes_key, string& res){
    //base64
    string raw;
    raw.resize((encrypted_info.size() / 4) * 3);

    int decoded_len = EVP_DecodeBlock((unsigned char*)raw.data(), \
        (const unsigned char*)encrypted_info.data(), \
        (int)encrypted_info.size());

    int padding = 0;
    if (encrypted_info.size() >= 1 && encrypted_info[encrypted_info.size() - 1] == '=') padding++;
    if (encrypted_info.size() >= 2 && encrypted_info[encrypted_info.size() - 2] == '=') padding++;
    raw.resize(decoded_len - padding);


    NSS data_NSS;
    set_NSS(raw, data_NSS);


    //AES
    string data_plained;
    data_plained.resize(data_NSS.cipher_text.size() + 16);
    if (aes_decrypt(data_NSS, aes_key, data_plained)){
        return 1;
    };
    res = data_plained;
    if (verbose){
        cout << data_plained << endl;
        //
        cout << "padding: " << padding << endl;

        cout << "data_iv: ";
        for (size_t k = 0; k < data_NSS.iv.size(); k++)
            printf("%02x", (unsigned char)data_NSS.iv[k]);
        printf("\n");

        cout << "data_ct: ";
        for (size_t k = 0; k < data_NSS.cipher_text.size(); k++)
            printf("%02x", (unsigned char)data_NSS.cipher_text[k]);
        printf("\n");
    }
    return 0;
}
int proc_db(PBES2& item2_PBES2, PBES2& a11_PBES2, string& item1){
    DataBase DB(path_DB.data(), SQLITE_OPEN_READONLY);
    if (DB.has_error()){
        //cout << "error key4.db. Path: " << path_DB << endl;
        return 1;
    }

    string item2;

    DB.prepare("SELECT item1 FROM metadata WHERE id='password'");
    if (DB.step() == SQLITE_ROW)
        item1.assign((const char*)DB.column_blob(), DB.column_bytes());
    if (item1.empty()) return 1;
    //item2
    DB.prepare("SELECT item2 FROM metadata WHERE id='password'");
    if (DB.step() == SQLITE_ROW)
        item2.assign((const char*)DB.column_blob(), DB.column_bytes());
    if (item2.empty()) return 1;
    if (set_PBES2(item2, item2_PBES2) == 1) return 1;

    //a11
    string a11;
    DB.prepare("SELECT a11 FROM nssPrivate WHERE substr(a0, -1) = X'04'");
    while (DB.step() == SQLITE_ROW){
        string potentiala11((const char*)DB.column_blob(), DB.column_bytes());
        if (potentiala11.size() == 164){ a11 = potentiala11; break; }
    }
    if (a11.empty()){
        //cout << "a11 not exists\n";
        return 1;
    }
    if (set_PBES2(a11, a11_PBES2) == 1) return 1;
    //cout << a11_PBES2.iterations;

    if (verbose){
        cout << "item1 size: " << item1.size() << endl;
        cout << "item2 size: " << item2.size() << endl;

        printf("item2_entry_salt: ");
        for (size_t k = 0; k < item2_PBES2.entry_salt.size(); k++)
            printf("%02x", (unsigned char)item2_PBES2.entry_salt[k]);
        printf("\n");

        cout << "a11 size: " << a11.size() << endl;
    }

    return 0;
}
int proc_json(string& logins){
    //--json
    ifstream f_logins(path_logins);
    if (!f_logins.is_open()){
        cout << "error open logins.json. Path: " << path_logins << endl;
        return 1;
    }
    string line;
    while (getline(f_logins, line)){
        logins += line;
    }
    //cout << logins << endl;
    f_logins.close();
    return 0;
}
path get_profile_path(){
    //C:\Users\0_0\AppData\Roaming\Mozilla\Firefox\Profiles
    char buf[MAX_PATH];
    GetEnvironmentVariableA("USERPROFILE", buf, MAX_PATH);
    path path_user_profile = path(buf).string();
    path path_firefox_profiles = path_user_profile / R"(AppData\Roaming\Mozilla\Firefox\Profiles)";
    return path_firefox_profiles;
}
bool exists(const LoginsPasswords& a, const LoginsPasswords& b){
    if (a.hostname == b.hostname && a.username == b.username && a.password == b.password) return 1;
    return 0;
}
int decode(vector <LoginsPasswords>& decoded_info){// paths are global
    //cout << path_DB << endl << path_logins;
    //cout << std::filesystem::current_path();
    string item1;
    PBES2 item2_PBES2;
    PBES2 a11_PBES2;

    //KDF
    string master_pass;//////////////////////TODO
    if (proc_db(item2_PBES2, a11_PBES2, item1)) return 1;
    string kdf_input;
    kdf_input.resize(20);

    string item1_master = item1 + master_pass;
    SHA1((const unsigned char*)item1_master.data(), item1_master.size(), (unsigned char*)kdf_input.data());

    string wrapped_key;
    wrapped_key.resize(a11_PBES2.keylen);

    PKCS5_PBKDF2_HMAC(\
        (const char*)kdf_input.data(), kdf_input.size(), \
        (const unsigned char*)a11_PBES2.entry_salt.data(), a11_PBES2.entry_salt.size(), \
        a11_PBES2.iterations, \
        EVP_sha256(), \
        a11_PBES2.keylen, \
        (unsigned char*)wrapped_key.data());

    //aes_key
    string aes_key;
    aes_key.resize(a11_PBES2.cipher_text.size() + 16);
    if (aes_decrypt(a11_PBES2, wrapped_key, aes_key)){
        return 1;
    };


    //======================================================decode
    //--json
    string logins;
    if (proc_json(logins)) return 1;


    /////
    vector <LoginsPasswords> encoded_info;
    int i = 0;
    int i_end = 0;
    while (true){
        LoginsPasswords data;

        i = logins.find("hostname", i);
        if (i == string::npos) break;
        i += strlen("hostname\":\"");
        i_end = logins.find('"', i);
        data.hostname = logins.substr(i, i_end - i);
        //cout << data.hostname << endl;

        i = logins.find("encryptedUsername", i_end);
        if (i != string::npos){
            i += strlen("encryptedUsername\":\"");
            i_end = logins.find('"', i);
            data.username = logins.substr(i, i_end - i);
        }

        i = logins.find("encryptedPassword", i_end);
        if (i != string::npos){
            i += strlen("encryptedPassword\":\"");
            i_end = logins.find('"', i);
            data.password = logins.substr(i, i_end - i);
        }

        encoded_info.emplace_back(data);
    }

    //for (size_t i = 0; i < encoded_info.size(); i++){
    //    cout << encoded_info[i].hostname << endl << encoded_info[i].username << endl\
    //        << encoded_info[i].password << endl;
    //}


    for (size_t i = 0; i < encoded_info.size(); i++){
        //string encrypted_info = encoded_info[i].username;
        LoginsPasswords res;
        res.hostname = encoded_info[i].hostname;
        if (get_plain_data(encoded_info[i].username, aes_key, res.username)){
            res.username = "error in decoding";
        }
        if (get_plain_data(encoded_info[i].password, aes_key, res.password)){
            res.password = "error in decoding";
        }
        // cout << res.hostname << endl;
        if (res.hostname.find("FirefoxAccounts") != string::npos) continue;
        
        decoded_info.push_back(res);

    }

    if (verbose){

        printf("a11_entry_salt: ");
        for (size_t k = 0; k < a11_PBES2.entry_salt.size(); k++)
            printf("%02x", (unsigned char)a11_PBES2.entry_salt[k]);
        printf("\n");

        printf("a11_iterations: %d\n", a11_PBES2.iterations);
        printf("a11_keylen    : %d\n", a11_PBES2.keylen);

        printf("a11_iv: ");
        for (size_t k = 0; k < a11_PBES2.iv.size(); k++)
            printf("%02x", (unsigned char)a11_PBES2.iv[k]);
        printf("\n");

        printf("a11_ct: ");
        for (size_t k = 0; k < a11_PBES2.cipher_text.size(); k++)
            printf("%02x", (unsigned char)a11_PBES2.cipher_text[k]);
        printf("\n");

        printf("kdf_input: ");
        for (size_t k = 0; k < kdf_input.size(); k++)
            printf("%02x", (unsigned char)kdf_input[k]);
        printf("\n");

        printf("wrapped_key: ");
        for (size_t k = 0; k < wrapped_key.size(); k++)
            printf("%02x", (unsigned char)wrapped_key[k]);
        printf("\n");

        printf("aes_key: ");
        for (size_t k = 0; k < aes_key.size(); k++)
            printf("%02x", (unsigned char)aes_key[k]);
        printf("  len: %zu\n", aes_key.size());


    }
    return 0;
}
void print_usage(){
    cout << "Usage:\n\
0 - try to find necessary paths in default directory and decrypt.\n\
1 - u have key4.db and logins.json next to this program.\n\
2 - write paths for key4.db and logins.json.\nResults will be shown at console and in file: result.txt.\n" << endl;
}
void print_result(vector <LoginsPasswords>& decoded_info){
    //-----out
    ofstream out("result.txt");
    if (!out.is_open()){
        cout << "error create " << "result.txt" << endl;
        return;
    }

    size_t dec_size = decoded_info.size();
    if (dec_size == 0){
        cout << "No data has succesfully decrypted.\n";
        out << "No data has succesfully decrypted.\n";
        return;
    }
    cout << "Succesful decrypted: " << decoded_info.size() << " counts.\n\n";
    out << "Succesful decrypted: " << decoded_info.size() << " counts.\n\n";
    if (dec_size == 0) return;
    for (const auto& i : decoded_info){
        cout << "****************************************************************************\n" << \
            "hostname: " << i.hostname << endl << \
            "username: " << i.username << endl << \
            "password: " << i.password << endl;
        out << "****************************************************************************\n" << \
            "hostname: " << i.hostname << "\n" << \
            "username: " << i.username << "\n" << \
            "password: " << i.password << "\n";
    }
    cout << "****************************************************************************\n" << endl;
    out << "****************************************************************************" << "\n";
}

int main(){
    //=============================prepare for get info from encrypted data
    int mode = 0;
    print_usage();
    cin >> mode;

    
    vector <LoginsPasswords> decoded_info;
    if (mode == 0){
        //C:\Users\0_0\AppData\Roaming\Mozilla\Firefox\Profiles
        path path_firefox_profiles = get_profile_path();
        string firefox_profiles = path_firefox_profiles.string();
        //cout << firefox_profiles;

        vector <string> profile_names;
        for (const auto& obj : directory_iterator(path_firefox_profiles)){
            if (obj.is_directory()){
                profile_names.push_back(obj.path().filename().string());
            }
        }

        //proc
        for (const auto& name : profile_names){
            path db_path = path_firefox_profiles / name / "key4.db";
            path json_path = path_firefox_profiles / name / "logins.json";
            //cout << name << endl << db_path.string() << endl << json_path.string() << endl << endl;
            if (!exists(db_path) || !exists(json_path)){
                //cout << "no\n";
                //cout << name << endl << db_path.string() << endl << json_path.string() << endl << endl;
                continue;
            }
            path_DB = db_path.string();
            path_logins = json_path.string();
            if (decode(decoded_info)) 
                continue;
        }

    }
    else if (mode == 1){
        char exe_buf[MAX_PATH];
        GetModuleFileNameA(nullptr, exe_buf, MAX_PATH);
        path exe_folder = path(exe_buf).parent_path();
        path db_path = exe_folder / "key4.db";
        path json_path = exe_folder / "logins.json";
        if (!exists(db_path) || !exists(json_path)){
            cout << "error find:\n" << db_path.string() << endl << json_path.string() << endl << endl;
        }
        else{
            path_DB = db_path.string();
            path_logins = json_path.string();
            //cout << "db: " << path_DB << endl << "json: " << path_logins << endl;
            if (decode(decoded_info)){
                cout << "error in decoding\n";
                return 0;
            }
        }
        
    }
    else{
        cout << "write path for key4.db: " << endl;
        cin >> path_DB;

        cout << "write path for logins.json: " << endl;
        cin >> path_logins;

        if (!exists(path_DB) || !exists(path_logins)){
            cout << "error find:\n" << path_DB << endl << path_logins << endl << endl;
        }
        else{
            if (decode(decoded_info)){
                cout << "error in decoding\n";
                return 0;
            }
        }
        
    }
    

    //---------remove repeatable data
    vector <LoginsPasswords> result;
    for (size_t i = 0; i < decoded_info.size(); i++){/////////////////////////////////O2 TODO ашч
        LoginsPasswords obj = decoded_info[i];
        bool flag = 1;
        for (const auto& added : result){
            if (exists(added, obj)){
                flag = 0;
                break;
            }
        }
        if (flag) result.push_back(obj);

    }
    
     

    print_result(result);
    cout << "Write any to exit\n";
    int stop;
    cin >> stop;
    return 0;
}