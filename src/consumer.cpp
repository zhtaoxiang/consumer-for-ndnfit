/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2015,  Regents of the University of California
 *
 * This file is part of ndn-group-encrypt (Group-based Encryption Protocol for NDN).
 * See AUTHORS.md for complete list of ndn-group-encrypt authors and contributors.
 *
 * ndn-group-encrypt is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * ndn-group-encrypt is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ndn-group-encrypt, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Haitao Zhang <zhtaoxiang@gmail.com>
 */
#include <ndn-group-encrypt/consumer.hpp>
#include <ndn-group-encrypt/error-code.hpp>
#include <ndn-group-encrypt/random-number-generator.hpp>
#include <ndn-group-encrypt/algo/rsa.hpp>
#include <ndn-group-encrypt/algo/aes.hpp>
#include <ndn-group-encrypt/algo/encryptor.hpp>
#include <ndn-group-encrypt/encrypted-content.hpp>
#include <ndn-group-encrypt/algo/encrypt-params.hpp>
#include <ndn-group-encrypt/decrypt-key.hpp>

#include <boost/filesystem.hpp>
#include <ndn-cxx/name.hpp>
#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/link.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <boost/asio.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <string>

namespace ndn {
namespace SampleConsumer {
    
    using namespace boost::posix_time;

const uint8_t SIG_INFO[] = {
  0x16, 0x1b, // SignatureInfo
      0x1b, 0x01, // SignatureType
          0x01,
      0x1c, 0x16, // KeyLocator
          0x07, 0x14, // Name
              0x08, 0x04,
                  0x74, 0x65, 0x73, 0x74,
              0x08, 0x03,
                  0x6b, 0x65, 0x79,
              0x08, 0x07,
                  0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72
};

const uint8_t SIG_VALUE[] = {
  0x17, 0x80, // SignatureValue
      0x2f, 0xd6, 0xf1, 0x6e, 0x80, 0x6f, 0x10, 0xbe, 0xb1, 0x6f, 0x3e, 0x31, 0xec,
      0xe3, 0xb9, 0xea, 0x83, 0x30, 0x40, 0x03, 0xfc, 0xa0, 0x13, 0xd9, 0xb3, 0xc6,
      0x25, 0x16, 0x2d, 0xa6, 0x58, 0x41, 0x69, 0x62, 0x56, 0xd8, 0xb3, 0x6a, 0x38,
      0x76, 0x56, 0xea, 0x61, 0xb2, 0x32, 0x70, 0x1c, 0xb6, 0x4d, 0x10, 0x1d, 0xdc,
      0x92, 0x8e, 0x52, 0xa5, 0x8a, 0x1d, 0xd9, 0x96, 0x5e, 0xc0, 0x62, 0x0b, 0xcf,
      0x3a, 0x9d, 0x7f, 0xca, 0xbe, 0xa1, 0x41, 0x71, 0x85, 0x7a, 0x8b, 0x5d, 0xa9,
      0x64, 0xd6, 0x66, 0xb4, 0xe9, 0x8d, 0x0c, 0x28, 0x43, 0xee, 0xa6, 0x64, 0xe8,
      0x55, 0xf6, 0x1c, 0x19, 0x0b, 0xef, 0x99, 0x25, 0x1e, 0xdc, 0x78, 0xb3, 0xa7,
      0xaa, 0x0d, 0x14, 0x58, 0x30, 0xe5, 0x37, 0x6a, 0x6d, 0xdb, 0x56, 0xac, 0xa3,
      0xfc, 0x90, 0x7a, 0xb8, 0x66, 0x9c, 0x0e, 0xf6, 0xb7, 0x64, 0xd1
};

    static const uint8_t DATA_CONTEN[] = {
    0xcb, 0xe5, 0x6a, 0x80, 0x41, 0x24, 0x58, 0x23,
    0x84, 0x14, 0x15, 0x61, 0x80, 0xb9, 0x5e, 0xbd,
    0xce, 0x32, 0xb4, 0xbe, 0xbc, 0x91, 0x31, 0xd6,
    0x19, 0x00, 0x80, 0x8b, 0xfa, 0x00, 0x05, 0x9c
    };
    
    static const std::string READ_ACCESS_REQUEST = "/org/openmhealth/zhehao/read_access_request/U/KEY/ksk-123/ID-CERT/123";
    static const std::string USER_PREFIX = "/org/openmhealth/zhehao";
    static const std::string USER_READ_PREFIX = "/org/openmhealth/zhehao/READ/fitness";
    static const std::string SCHEDULE_NAME = "schedule_name";
    static const std::string DATA_PREFIX = "/org/openmhealth/zhehao/SAMPLE";
    static const Name uKeyName("/U/KEY");
    static const Name uName("/U");
    static Buffer fixtureUEKeyBuf;
    static Buffer fixtureUDKeyBuf;
    static const Link NO_LINK;

      

    static const std::string DATABASE = "/tmp/consumer-key.db";
    
    class SampleConsumer : noncopyable
    {
    public:
        SampleConsumer();
        ~SampleConsumer();
        void onRegisterFailed(const Name& prefix, const std::string& reason);
        void onRequestInterest(const InterestFilter& filter, const Interest& interest);
        void onTimeout(const Interest& interest);
        void onRequestResponse(const Interest& interest, const Data& data);
        void run();
        void consumeData();
        void requestAccess();
    private:
        boost::asio::io_service m_ioService;
        ndn::Face m_face;
        ndn::util::Scheduler m_scheduler;
        KeyChain m_keyChain;
        Link link;
        ndn::gep::Consumer consumer;
        IdentityCertificate cert;
    };
    
    SampleConsumer::SampleConsumer()
    : m_face(m_ioService) // Create face with io_service object
    , m_scheduler(m_ioService)
    , link(USER_READ_PREFIX, {{10, "/a"}})
    , consumer(m_face, Name("/org/openmhealth/zhehao/READ/fitness"), uName, DATABASE, NO_LINK, ([](Link & in_link, KeyChain & in_keyChain){in_keyChain.sign(in_link); return in_link;}(link, m_keyChain)))
    {

        ndn::gep::RandomNumberGenerator rng;
        RsaKeyParams params;
        // generate user key
        fixtureUDKeyBuf = ndn::gep::algo::Rsa::generateKey(rng, params).getKeyBits();
        fixtureUEKeyBuf = ndn::gep::algo::Rsa::deriveEncryptKey(fixtureUDKeyBuf).getKeyBits();

    // generate certificate
    cert.setName(Name("/U/KEY/ksk-123/ID-CERT/123"));
    PublicKey contentPubKey(fixtureUEKeyBuf.buf(), fixtureUEKeyBuf.size());
    cert.setPublicKeyInfo(contentPubKey);
    cert.encode();

    Block sigInfoBlock(SIG_INFO, sizeof(SIG_INFO));
    Block sigValueBlock(SIG_VALUE, sizeof(SIG_VALUE));

    Signature sig(sigInfoBlock, sigValueBlock);
    cert.setSignature(sig);
        
        consumer.addDecryptionKey(uKeyName, fixtureUDKeyBuf);
        consumer.addDecryptionKey(Name("/U/ksk-123"), fixtureUDKeyBuf);
        consumer.addDecryptionKey(Name("/U/KEY/ksk-123/ID-CERT/123"), fixtureUDKeyBuf);
    }

    SampleConsumer::~SampleConsumer() {
        std::remove(DATABASE.c_str());
    }

    void SampleConsumer::run()
    {
        //accept incoming register interest
        m_face.setInterestFilter(uName,
                                 bind(&SampleConsumer::onRequestInterest, this, _1, _2),
                                 RegisterPrefixSuccessCallback(),
                                 bind(&SampleConsumer::onRegisterFailed, this, _1, _2));

        m_scheduler.scheduleEvent(time::seconds(1), 
                                  bind(&SampleConsumer::requestAccess, this));
        m_scheduler.scheduleEvent(time::seconds(20), 
                                  bind(&SampleConsumer::consumeData, this));
        

        m_ioService.run();
    }

    void SampleConsumer::consumeData() {
        std::cout << "consume data " << std::endl;
        consumer.consume(Name("/org/openmhealth/zhehao/SAMPLE/fitness/20160321T092000"), 
                   [&](const Data& data, const Buffer& result){
                     std::cout << "Successfully received data" << std::endl;
                     const uint8_t * resultArray = result.buf();
                     std::cout << "the size of received data content is " << sizeof(DATA_CONTEN) << std::endl;
                     for(uint8_t i = 0; i < sizeof(DATA_CONTEN); i ++) {
                         if(DATA_CONTEN[i] != resultArray[i]) {
                             std::cout << "byte " << i << " is different" << std::endl;
                         }
                     }
                   },
                   [&](const ndn::gep::ErrorCode& code, const std::string& str){
                     std::cerr << "failed to receive data" << std::endl;
                   });
    }

    void SampleConsumer::requestAccess() 
    {
       

        Interest interest;
        interest.setName(Name(READ_ACCESS_REQUEST));
        interest.setInterestLifetime(time::milliseconds(1000));

       
        m_face.expressInterest(interest, 
                               bind(&SampleConsumer::onRequestResponse, this, _1, _2),
                               bind(&SampleConsumer::onTimeout, this, _1));
    }
    
    void SampleConsumer::onRequestInterest(const InterestFilter& filter, const Interest& interest) {
        std::cout << "<< I: " << interest << std::endl;
        shared_ptr<Data> uEKeyData = make_shared<Data>(cert.wireEncode());
        uEKeyData->setName(cert.getName());
        //uEKeyData->setContent(cert.);
        //m_keyChain.sign(*uEKeyData);
        m_face.put(*uEKeyData);
        //m_face.put(cert);
    }

    void SampleConsumer::onRequestResponse(const Interest& interest, const Data& data)
    {
        std::cout << "get read access" << std::endl;
    }

    
    void SampleConsumer::onRegisterFailed(const Name& prefix, const std::string& reason)
    {
        std::cerr << "ERROR: Failed to register prefix \""
        << prefix << "\" in local hub's daemon (" << reason << ")"
        << std::endl;
    }
    
    void SampleConsumer::onTimeout(const Interest& interest){
        std::cout << "Time out I: " << interest << std::endl;
    }
    
} // namespace gep
} // namespace ndn


int main()
{
    ndn::SampleConsumer::SampleConsumer sampleConsumer;
    try {
        sampleConsumer.run();
    }
    catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
    }
    return 0;
}
