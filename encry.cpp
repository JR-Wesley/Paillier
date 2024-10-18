#include <iostream>
#include <fstream>
#include <iomanip>

#include <ctime>
#include <NTL/ZZ.h>

using namespace std;
using namespace NTL;

unsigned int addr_param = 0;
unsigned int addr_enc = 0, enc_golden = 0;
unsigned int addr_dec = 0, dec_golden = 0;
unsigned int addr_add = 0, add_golden = 0;
unsigned int addr_mul = 0, mul_golden = 0;

enum length{
    l2048 = 0,
    l4096 = 1,
    l2050 = 2,
    l4100 = 3,
};

// L函数
ZZ L_function(const ZZ &x, const ZZ &n) {
    return (x - 1) / n;
}

void keyGeneration(ZZ &p, ZZ &q, ZZ &n, ZZ &phi, ZZ &lambda, ZZ &g, ZZ &lambdaInverse, ZZ &r, const long &k);
ZZ encrypt(const ZZ &m, const ZZ &n, const ZZ &g, const ZZ &r);
ZZ decrypt(const ZZ &c, const ZZ &n, const ZZ &lambda, const ZZ &lambdaInverse);
void homoAdd(const ZZ &c1, const ZZ &c2, const ZZ &n, const ZZ &lambda, const ZZ &lambdaInverse);
void homoMul(const ZZ &c1, const ZZ &m2, const ZZ &n, const ZZ &lambda, const ZZ &lambdaInverse);
void outputNum(ZZ num, ofstream &fs, unsigned int &addr, int size_sel);

int main()
{
    // p, q 长度1025，多一位，以保证 n=pq>m
    long k = 1025;
    ZZ p, q, n, phi, lambda, lambdaInverse, g, r;
    ZZ m1, m2, c1, c2, m1_d, m2_d;
    keyGeneration(p, q, n, phi, lambda, g, lambdaInverse, r, k);
/*
    cout << "请输入需要加密的明文消息1 : ";
    cin >> m1;
    cout << "请输入需要加密的明文消息2 : ";
    cin >> m2;
*/
// 循环
    for(int l = 0; l < 4; l++){
    cout << "----------------------------------------------------明文-----------------------------------------------------" << endl;
        // 默认初始化为两个 2048 位的数，为明文
        // m1 = conv<ZZ>("22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222122222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222");
        // m2 = conv<ZZ>("22333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333331333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333");
        
        RandomLen(m1, 2048);
        RandomLen(m2, 2048);

        long k1 = NumBits(m1);
        long k2 = NumBits(m2);
        cout << "明文1 : " << m1 << endl;
        cout << "明文位宽 : " << k1 << endl;
        cout << "明文2 : " << m2 << endl;
        cout << "明文位宽 : " << k2 << endl;

        c1 = encrypt(m1, n, g, r);
        c2 = encrypt(m2, n, g, r);
        m1_d = decrypt(c1, n, lambda, lambdaInverse);
        m2_d = decrypt(c2, n, lambda, lambdaInverse);
        cout << "----------------------------------------------------加密阶段-----------------------------------------------------" << endl;
        cout << "密文输出1 : " << c1 << endl;
        cout << "密文输出2 : " << c2 << endl;
        cout << "密文位宽： " << NumBits(c1) << endl;

        if(m1_d == m1 & m2_d == m2){
            cout << ">> 加解密 正确" << endl;
        } else {
            cout << ">> 加解密 错误" << endl;
        }
    // ==================== write data to file ====================

    // ==================== 2048 message + 2048 random number ====================
    // m1,  r -> c1
        ofstream encFile;
        encFile.open("./data/enc.dat", std::ios_base::app);
        if (encFile.is_open()) {
        } else {
    cout << "Unable to open the file." << std::endl;
            return 0;
        }

        outputNum(m1, encFile, addr_enc, l2050);
        outputNum(r, encFile, addr_enc, l2050);
        encFile.close();

        ofstream encGoldFile;
        encGoldFile.open("./data/enc_golden.dat", std::ios_base::app);
        if (encGoldFile.is_open()) {
        } else {
    cout << "Unable to open the file." << std::endl;
            return 0;
        }

        outputNum(c1, encGoldFile, enc_golden, l4100);
        encGoldFile.close();

    // ==================== 4096 ciphertext1 ====================
    // c1 -> m1
        ofstream decFile;
        decFile.open("./data/dec.dat", std::ios_base::app);
        if (decFile.is_open()) {
        } else {
    cout << "Unable to open the file." << std::endl;
            return 0;
        }

        outputNum(c1, decFile, addr_dec, l4100);
        decFile.close();

        ofstream decGoldFile;
        decGoldFile.open("./data/dec_golden.dat", std::ios_base::app);
        if (decGoldFile.is_open()) {
        } else {
    cout << "Unable to open the file." << std::endl;
            return 0;
        }

        outputNum(m1, decGoldFile, dec_golden, l2050);
        decGoldFile.close();

        homoAdd(c1, c2, n, lambda, lambdaInverse);
        homoMul(c1, m2, n, lambda, lambdaInverse);

    }
    return 0;
}

/* 密钥生成函数
 *
 * 参数：
 *  p：大质数
 *  q：大质数
 *  n = p * q
 *  phi = (p - 1) * (q - 1)
 *  lambda = lcm(p - 1, q - 1) = (p - 1) * (q - 1) / gcd(p - 1, q - 1)
 *  g = n + 1
 *  lamdaInverse = lambda^{-1} mod n^2
 *  k : 大质数的位宽
 * 
 * 功能：
 * 生成大质数p, q 生成公钥(n, g) 密钥(lambda, mu)
 * 其中使用了g=n+1的优化方法，mu=lambda_inverse
 */
void keyGeneration(ZZ &p, ZZ &q, ZZ &n, ZZ &phi, ZZ &lambda, ZZ &g, ZZ &lambdaInverse, ZZ &r, const long &k)
{
    cout << "--------------------------------------------------密钥生成阶段---------------------------------------------------" << endl;

    GenPrime(p, k), GenPrime(q, k);
    n = p * q;
    g = n + 1;
    phi = (p - 1) * (q - 1);
    if(GCD(n, phi) == 1)
        cout << "生成成功" << endl;
    lambda = phi / GCD(p - 1, q - 1);
    lambdaInverse = InvMod(lambda, n);
    r = RandomBnd(n);
    cout << "大质数生成 " << endl;
    cout << "p = " << p << endl;
    cout << "q = " << q << endl;
    cout << "---------------------------------------------------------------------------------------------------------------" << endl;
    cout << "公钥(n, g) : " << endl;
    cout << "n = " << n << endl;
    cout << "g = " << g << endl;
    cout << "---------------------------------------------------------------------------------------------------------------" << endl;
    cout << "私钥(lambda, mu) : " << endl;
    cout << "lambda = " << lambda << endl;
    cout << "mu = " << lambdaInverse << endl;
    cout << "p 位宽  " << NumBits(p) << "  q 位宽  " << NumBits(q) << "  n 位宽  " << NumBits(n);
    cout << "  lambda位宽  " << NumBits(lambda) << "  u 位宽 " << NumBits(lambdaInverse) << endl;

// ==================== 2050 n & 4100 N^2 & 4100 paramr1 & 2050 paramr2 & 2050 lambda & 2050 u ===============
    ofstream paramFile;
    paramFile.open("./data/param.dat");
    if (paramFile.is_open()) {
    } else {
cout << "Unable to open the file." << std::endl;
        return;
    }

    outputNum(n, paramFile, addr_param, l2050);
    ZZ n_squre = n * n;
    outputNum(n_squre, paramFile, addr_param, l4100);
    // 9 * 256
    ZZ base2 = conv<ZZ>("2");
    ZZ R1 = conv<ZZ>("2304");
    R1 = PowerMod(base2, R1, n);
    R1 = (R1 * R1) % n;
    outputNum(R1, paramFile, addr_param, l2050);
    // 17 * 256
    ZZ R2 = conv<ZZ>("4352");
    R2 = PowerMod(base2, R2, n);
    R2 = (R2 * R2) % n_squre;
    outputNum(R2, paramFile, addr_param, l4100);
    // lambada/ u
    outputNum(lambda, paramFile, addr_param, l2050);
    outputNum(lambdaInverse, paramFile, addr_param, l2050);

    paramFile.close();

}

/* 加密函数
 *
 * 参数：
 *  m ：需要加密的明文消息
 *  (n, g) ：公钥
 *
 * 返回值：
 * r: 对m加密后得到的密文
 */
ZZ encrypt(const ZZ &m, const ZZ &n, const ZZ &g, const ZZ &r)
{
    // 生成一个随机数 r < n
    // r = RandomBnd(n);
    //ZZ c = (PowerMod(g, m, n * n) * PowerMod(r, n, n * n) ) % (n * n);
    ZZ c = ((m * n + 1) * PowerMod(r, n, n * n) ) % (n * n);
    
    return c;
}

/* 解密函数
 * 
 * 参数：
 *  c：密文
 *  (lambda，lamdaInverse)： 私钥
 * 
 * 返回值：
 * m 根据c解密的明文
 */
ZZ decrypt(const ZZ &c, const ZZ &n, const ZZ &lambda, const ZZ &lambdaInverse)
{
    ZZ m = (L_function(PowerMod(c, lambda, n * n), n) * lambdaInverse) % n;

    return m;
}

/* 同态加函数
 * 
 * 参数：
 *  c1：密文1
 *  c2：密文2
 *  (lambda，lamdaInverse)： 私钥，用于验证结果正确性
 * 
 * 功能：
 * 两个密文同态加：(c1*c2) mod (n^2)
 * 并验证同台加的结果和明文和相等
 */
void homoAdd(const ZZ &c1, const ZZ &c2, const ZZ &n, const ZZ &lambda, const ZZ &lambdaInverse)
{
    cout << "----------------------------------------------------验证同态加-----------------------------------------------------" << endl;

    ZZ c_sum = (c1 * c2) % (n * n);
    cout << "密文相加 : " << c_sum << endl;
    
    // 明文验证
    ZZ m1 = decrypt(c1, n, lambda, lambdaInverse);
    ZZ m2 = decrypt(c2, n, lambda, lambdaInverse);
    ZZ ss_sum = (m1 + m2)%n;
    // 同态解密
    ZZ m_sum = decrypt(c_sum, n, lambda, lambdaInverse);
    cout << "解密得到 : " << m_sum << endl;
    if(m_sum == ss_sum){
        cout << ">> 同态加 正确" << endl;
    } else {
        cout << ">> 同态加 错误" << endl;
    }
    
// ==================== 4096 ciphertext1 + 4096 ciphertext2 
    ofstream addFile;
    addFile.open("./data/homoAdd.dat", std::ios_base::app);
    if (addFile.is_open()) {
    } else {
cout << "Unable to open the file." << std::endl;
        return;
    }

    outputNum(c1, addFile, addr_add, l4100);
    outputNum(c2, addFile, addr_add, l4100);
    addFile.close();

    ofstream addGoldFile;
    addGoldFile.open("./data/homoAdd_golden.dat", std::ios_base::app);
    if (addGoldFile.is_open()) {
    } else {
cout << "Unable to open the file." << std::endl;
        return;
    }

    outputNum(c_sum, addGoldFile, add_golden, l4100);
    addGoldFile.close();

    return;
}

/* 同态数乘函数
 * 
 * 参数：
 *  c1：密文
 *  m2: 明文
 *  n：公钥
 *  (lambda, u) 密钥，用于验证结果正确性
 * 
 * 功能：
 *  mul = c1^m2 mod (n^2)
 *  判断mul是否等于c1的明文m1和明文m2的积
 */
void homoMul(const ZZ &c1, const ZZ &m2, const ZZ &n, const ZZ &lambda, const ZZ &lambdaInverse)
{
cout << "----------------------------------------------------验证同态乘-----------------------------------------------------" << endl;

    ZZ c_mul = PowerMod(c1, m2, n*n);
cout << "同态数乘 : " << c_mul << endl;

    // 明文验证
    ZZ m1 = decrypt(c1, n, lambda, lambdaInverse);    
    ZZ mm_mul = (m1*m2)%n;
cout << "明文相乘 : " << mm_mul << endl;
    // 同态解密
    ZZ m_mul = decrypt(c_mul, n, lambda, lambdaInverse);
    if(m_mul == mm_mul){
cout << ">> 同态数乘 正确" << endl;
    } else {
cout << ">> 同态数乘 错误" << endl;
    }

// ==================== 4096 ciphertext1 + 2048 message2 
    ofstream mulFile;
    mulFile.open("./data/homoMul.dat", std::ios_base::app);
    if (mulFile.is_open()) {
    } else {
cout << "Unable to open the file." << std::endl;
        return ;
    }

    outputNum(c1, mulFile, addr_mul, l4100);
    outputNum(m2, mulFile, addr_mul, l2050);
    mulFile.close();

    ofstream mulGoldFile;
    mulGoldFile.open("./data/homoMul_golden.dat", std::ios_base::app);
    if (mulGoldFile.is_open()) {
    } else {
cout << "Unable to open the file." << std::endl;
        return ;
    }

    outputNum(c_mul, mulGoldFile, mul_golden, l4100);
    mulGoldFile.close();

    return;
}

// ouput 16 * 256bit
// 地址传引用，会逐渐累加
// m1 m2 2050bits; c1 c2 4010 bits
// size_sel: 0 - 2048长度；1 - 4096长度; 2 - 2050长度；3 - 4050长度
void outputNum(ZZ num, ofstream &fs, unsigned int &addr, int size_sel){
    unsigned int doublebytes[16] = {0};

    unsigned int size;
    if(size_sel == l2048){
        size = 8;
    } else if(size_sel == l4096){
        size = 16;
    } else if(size_sel == l2050){
        size = 9;
    } else if(size_sel == l4100) {
        size = 17;
    } else {
        cout << "length not supported." << endl;
        return;
    }

    for(int i = 0; i < size; i++){
        fs << "@" << setw(10) << setfill('0') << hex << addr << " ";
// cout << "----------------------------------------------------addr-----------------------------------------------------" << endl;
        for(int j = 0; j < 16; j++){
            doublebytes[j] = num % (1 << 16);
            num = num / (1 << 16);
// cout << "res " << hex << num << endl;
// cout << "hex " << hex << doublebytes[j] << endl;
        }
        // 倒序输出，高位在前
        for(int j = 0; j < 16; j++){
            fs << setw(4) << setfill('0') << hex << doublebytes[15 - j];
        }
        fs << endl;
        addr++;
    }
    return;
}