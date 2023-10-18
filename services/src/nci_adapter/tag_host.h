/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef TAG_HOST_H
#define TAG_HOST_H
#include <mutex>
#include "itag_host.h"
#include "synchronize_event.h"
#include "nfc_nci_adaptor.h"

#ifdef NCI_PROTOCOL_MIFARE
#undef NCI_PROTOCOL_MIFARE
#endif
#define NCI_PROTOCOL_MIFARE ((*NfcNciAdaptor::pNfaProprietaryCfg)->pro_protocol_mfc)

#ifdef NCI_PROTOCOL_15693
#undef NCI_PROTOCOL_15693
#endif
#define NCI_PROTOCOL_15693 ((*NfcNciAdaptor::pNfaProprietaryCfg)->pro_protocol_15693)

#ifdef NCI_PROTOCOL_B_PRIME
#undef NCI_PROTOCOL_B_PRIME
#endif
#define NCI_PROTOCOL_B_PRIME ((*NfcNciAdaptor::pNfaProprietaryCfg)->pro_protocol_b_prime)

#ifdef NCI_DISCOVERY_TYPE_POLL_B_PRIME
#undef NCI_DISCOVERY_TYPE_POLL_B_PRIME
#endif
#define NCI_DISCOVERY_TYPE_POLL_B_PRIME \
    ((*NfcNciAdaptor::pNfaProprietaryCfg)->pro_discovery_b_prime_poll)

#ifdef NCI_DISCOVERY_TYPE_LISTEN_B_PRIME
#undef NCI_DISCOVERY_TYPE_LISTEN_B_PRIME
#endif
#define NCI_DISCOVERY_TYPE_LISTEN_B_PRIME \
    ((*NfcNciAdaptor::pNfaProprietaryCfg)->pro_discovery_b_prime_listen)

#ifdef NFC_PROTOCOL_T5T
#undef NFC_PROTOCOL_T5T
#endif
#define NFC_PROTOCOL_T5T NFC_PROTOCOL_T5T_(NfcNciAdaptor::GetInstance().NfcGetNciVersion())
#define NFC_PROTOCOL_T5T_(x) \
    (((x) == NCI_VERSION_2_0) ? NCI_PROTOCOL_T5T : NCI_PROTOCOL_15693)

namespace OHOS {
namespace NFC {
namespace NCI {
class TagHost : public ITagHost {
public:
    static const int DATA_BYTE2 = 2;
    static const int DATA_BYTE3 = 3;
    static const int DATA_BYTE4 = 4;
    static const int DATA_BYTE5 = 5;
    static const int DATA_BYTE6 = 6;
    static const int DATA_BYTE7 = 7;
    static const int DATA_BYTE8 = 8;
    static const int DATA_BYTE9 = 9;
    // NFC_B
    static const int NCI_APP_DATA_LENGTH = 4;
    static const int NCI_PROTOCOL_INFO_LENGTH = 3;
    // MifareUltralight
    static const int NCI_MIFARE_ULTRALIGHT_C_RESPONSE_LENGTH = 16;
    static const int NCI_MIFARE_ULTRALIGHT_C_BLANK_CARD = 0;
    static const int NCI_MIFARE_ULTRALIGHT_C_VERSION_INFO_FIRST = 0x02;
    static const int NCI_MIFARE_ULTRALIGHT_C_VERSION_INFO_SECOND = 0x00;
    static const int NCI_MIFARE_ULTRALIGHT_C_NDEF_CC = 0xE1;
    static const int NCI_MIFARE_ULTRALIGHT_C_NDEF_MAJOR_VERSION = 0x20;
    static const int NCI_MIFARE_ULTRALIGHT_C_NDEF_TAG_SIZE = 0x06;
    // Iso15693
    static const int NCI_POLL_LENGTH_MIN = 2;
    static const int DEFAULT_PRESENCE_CHECK_WATCH_DOG_TIMEOUT = 125;
    // T1T~T4T for NDEF tag
    static const auto NDEF_UNKNOWN_TYPE = -1;
    static const auto NDEF_TYPE1_TAG = 1;
    static const auto NDEF_TYPE2_TAG = 2;
    static const auto NDEF_TYPE3_TAG = 3;
    static const auto NDEF_TYPE4_TAG = 4;
    static const auto NDEF_MIFARE_CLASSIC_TAG = 101;

    static const auto TARGET_TYPE_UNKNOWN = 0;
    static const auto TARGET_TYPE_ISO14443_3A = 1;
    static const auto TARGET_TYPE_ISO14443_3B = 2;
    static const auto TARGET_TYPE_ISO14443_4 = 3;
    static const auto TARGET_TYPE_FELICA = 4;
    static const auto TARGET_TYPE_V = 5;
    static const auto TARGET_TYPE_NDEF = 6;
    static const auto TARGET_TYPE_NDEF_FORMATABLE = 7;
    static const auto TARGET_TYPE_MIFARE_CLASSIC = 8;
    static const auto TARGET_TYPE_MIFARE_UL = 9;

    // NfcF, Felica
    static const int SENSF_RES_LENGTH = 8;
    static const int F_POLL_LENGTH = 10;

public:
    TagHost(const std::vector<int>& tagTechList,
            const std::vector<int>& tagRfDiscIdList,
            const std::vector<int>& tagActivatedProtocols,
            const std::string& uid,
            const std::vector<std::string>& tagPollBytes,
            const std::vector<std::string>& tagActivatedBytes,
            const int connectedTechIndex);
    ~TagHost() override;
    bool Connect(int technology) override;
    bool Disconnect() override;
    bool Reconnect() override;
    int Transceive(std::string& request, std::string& response) override;

    // get the tag related technologies or uid info.
    std::vector<int> GetTechList() override;
    int GetConnectedTech() override;
    void RemoveTech(int tech) override;
    std::vector<AppExecFwk::PacMap> GetTechExtrasData() override;
    std::string GetTagUid() override;
    int GetTagRfDiscId() override;

    // functions for ndef tag only.
    std::string ReadNdef() override;
    bool WriteNdef(std::string& data) override;
    bool IsNdefFormatable() override;
    bool FormatNdef(const std::string& key) override;
    bool SetNdefReadOnly() override;
    bool IsNdefMsgContained(std::vector<int>& ndefInfo) override;
    std::string FindNdefTech() override;

    // functions for checking the tag field on or not.
    bool FieldOnCheckingThread() override;
    bool IsTagFieldOn() override;
    void OnFieldChecking(TagDisconnectedCallBack callback, int delayedMs) override;
    void OffFieldChecking() override;

    void SetTimeout(int timeout, int technology) override;
private:
    AppExecFwk::PacMap ParseTechExtras(int index);
    void FieldCheckingThread(TagHost::TagDisconnectedCallBack callback, int delayedMs);
    void PauseFieldChecking();
    void ResumeFieldChecking();
    void AddNdefTechToTagInfo(int tech, int discId, int actProto, AppExecFwk::PacMap pacMap);
    int GetNdefType(int protocol) const;
    bool IsUltralightC();

    void DoTargetTypeIso144433a(AppExecFwk::PacMap &pacMap, int index);
    void DoTargetTypeIso144433b(AppExecFwk::PacMap &pacMap, int index);
    void DoTargetTypeIso144434(AppExecFwk::PacMap &pacMap, int index);
    void DoTargetTypeV(AppExecFwk::PacMap &pacMap, int index);
    void DoTargetTypeF(AppExecFwk::PacMap &pacMap, int index);
    void DoTargetTypeNdef(AppExecFwk::PacMap &pacMap);

    static OHOS::NFC::SynchronizeEvent fieldCheckWatchDog_;
    std::mutex mutex_ {};

    // tag datas for tag dispatcher
    std::vector<int> tagTechList_;
    std::vector<AppExecFwk::PacMap> tagTechExtras_;
    std::vector<int> tagRfDiscIdList_;
    std::vector<int> tagRfProtocols_;
    std::string tagUid_;
    std::vector<std::string> tagPollBytes_;
    std::vector<std::string> tagActivatedBytes_;

    // tag connection datas
    int connectedTagDiscId_; // multiproto card can have different values
    int connectedTechIndex_; // index to find value in arrays of tag data
    volatile bool isTagFieldOn_;
    volatile bool isFieldChecking_;
    volatile bool isPauseFieldChecking_;
    bool addNdefTech_;
    std::vector<int> technologyList_ {};

    /* NDEF */
    static const int NDEF_INFO_SIZE = 2; // includes size + mode;
    static const int NDEF_SIZE_INDEX = 0;
    static const int NDEF_MODE_INDEX = 1;
    AppExecFwk::PacMap ndefExtras_;
};
}  // namespace NCI
}  // namespace NFC
}  // namespace OHOS
#endif  // TAG_HOST_H
