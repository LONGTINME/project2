#include "ES.h"
#include "RSU.h"
#include "MyElgamal.h"
#include <iostream>

using namespace CryptoPP;

ES::ES(const ElGamal::PublicKey &publicKey, const ElGamal::PrivateKey &privateKey)
    : esPublicKey_(publicKey), esPrivateKey_(privateKey) {}

void ES::ReceiveTask(const std::string &encryptedPseudonymAndTime, const std::string &encryptedTask) {
    //std::cout << "ES: Decrypting pseudonym and time..." << std::endl;
    currentPseudonymAndTime_ = ElgamalDecrypt(encryptedPseudonymAndTime, esPrivateKey_);
    //std::cout << "ES: Decrypted pseudonym and time: " << currentPseudonymAndTime_ << std::endl;

   //std::cout << "ES: Decrypting task..." << std::endl;
    currentTask_ = ElgamalDecrypt(encryptedTask, esPrivateKey_);
    //std::cout << "ES: Decrypted task: " << currentTask_ << std::endl;

    // 提取任务标号和噪声标号
    std::string taskPrefix = "task_data_";
    std::string noisePrefix = "random_noise_";
    std::size_t taskPos = currentTask_.find(taskPrefix);
    std::size_t noisePos = currentTask_.find(noisePrefix);

    if (taskPos != std::string::npos && noisePos != std::string::npos) {
        std::string taskNumber = currentTask_.substr(taskPos + taskPrefix.length(), noisePos - (taskPos + taskPrefix.length()));
        std::string noiseNumber = currentTask_.substr(noisePos + noisePrefix.length());

        // 生成结果字符串
        currentResponse_ = "no_" + taskNumber + "||re_" + noiseNumber;
    } else {
        currentResponse_ = "Invalid task format"; // 如果格式不匹配，返回错误消息
    }

    //std::cout << "ES: Generated response: " << currentResponse_ << std::endl;
}


void ES::SendResponseToRSU(RSU &rsu) {
    std::string pseudonymAndTimeAndVR = currentPseudonymAndTime_ + "||" + currentResponse_;
    //std::cout << "ES: kaishijiami" << std::endl;
    
    // 输出调试信息以确认拼接后的字符串内容
   // std::cout << "pseudonymAndTimeAndVR: " << pseudonymAndTimeAndVR << std::endl;
    
    std::string encryptedResponse;
    try {
        encryptedResponse = ElgamalEncrypt(pseudonymAndTimeAndVR, rsu.getPublicKey());
       // std::cout << "ES: Encryption successful. Encrypted Response: " << encryptedResponse << std::endl;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "ES: CryptoPP Exception during encryption: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "ES: Standard Exception during encryption: " << e.what() << std::endl;
    }
    
    //std::cout << "ES: Sending response to RSU..." << std::endl;
    rsu.ReceiveResponseFromES(encryptedResponse);
}
