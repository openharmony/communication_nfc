/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "hostcardemulationmanager_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "host_card_emulation_manager.h"
#include "nfc_sdk_common.h"
#include "nfc_service_ipc_interface_code.h"

namespace OHOS {
    using namespace OHOS::NFC::KITS;
    using namespace OHOS::NFC;
    using namespace OHOS::Security::AccessToken;

class IHceCmdCallbackImpl : public IHceCmdCallback {
public:
    IHceCmdCallbackImpl() {}

    virtual ~IHceCmdCallbackImpl() {}

public:
    void OnCeApduData(const std::vector<uint8_t> &data) override
    {
    }

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

    constexpr const auto FUZZER_THRESHOLD = 4;
    constexpr const auto INT_TO_BOOL_DIVISOR = 2;

    void ConvertToUint32s(const uint8_t* ptr, uint32_t* outPara, uint16_t outParaLen)
    {
        for (uint16_t i = 0 ; i < outParaLen ; i++) {
            // 4 uint8s compose 1 uint32 , 8 16 24 is bit operation, 2 3 4 are array subscripts.
            outPara[i] = (ptr[i * 4] << 24) | (ptr[(i * 4) + 1 ] << 16) | (ptr[(i * 4) + 2] << 8) | (ptr[(i * 4) + 3]);
        }
    }

    void FuzzOnHostCardEmulationDataNfcA(const uint8_t* data, size_t size)
    {
        std::weak_ptr<NfcService> nfcService;
        std::weak_ptr<NCI::INciCeInterface> nciCeProxy;
        std::weak_ptr<CeService> ceService;
        std::shared_ptr<HostCardEmulationManager> manager =
            std::make_shared<HostCardEmulationManager>(nfcService, nciCeProxy, ceService);
        std::vector<uint8_t> datas;
        uint32_t timeOutArray[1];
        ConvertToUint32s(data, timeOutArray, 1);
        datas.push_back(timeOutArray[0]);
        manager->OnHostCardEmulationDataNfcA(datas);
    }

    void FuzzOnCardEmulationActivated(const uint8_t* data, size_t size)
    {
        std::weak_ptr<NfcService> nfcService;
        std::weak_ptr<NCI::INciCeInterface> nciCeProxy;
        std::weak_ptr<CeService> ceService;
        std::shared_ptr<HostCardEmulationManager> manager =
            std::make_shared<HostCardEmulationManager>(nfcService, nciCeProxy, ceService);
        manager->OnCardEmulationActivated();
    }

    void FuzzOnCardEmulationDeactivated(const uint8_t* data, size_t size)
    {
        std::weak_ptr<NfcService> nfcService;
        std::weak_ptr<NCI::INciCeInterface> nciCeProxy;
        std::weak_ptr<CeService> ceService;
        std::shared_ptr<HostCardEmulationManager> manager =
            std::make_shared<HostCardEmulationManager>(nfcService, nciCeProxy, ceService);
        manager->OnCardEmulationDeactivated();
    }

    void FuzzRegHceCmdCallback(const uint8_t* data, size_t size)
    {
        std::weak_ptr<NfcService> nfcService;
        std::weak_ptr<NCI::INciCeInterface> nciCeProxy;
        std::weak_ptr<CeService> ceService;
        std::shared_ptr<HostCardEmulationManager> manager =
            std::make_shared<HostCardEmulationManager>(nfcService, nciCeProxy, ceService);
        sptr<IHceCmdCallbackImpl> iHceCmdCallbackImpl =
            sptr<IHceCmdCallbackImpl>(new (std::nothrow) IHceCmdCallbackImpl());
        std::string type = NfcSdkCommon::BytesVecToHexString(data, size);
        AccessTokenID callerToken = 0;
        manager->RegHceCmdCallback(iHceCmdCallbackImpl, type, callerToken);
    }

    void FuzzUnRegHceCmdCallback(const uint8_t* data, size_t size)
    {
        std::weak_ptr<NfcService> nfcService;
        std::weak_ptr<NCI::INciCeInterface> nciCeProxy;
        std::weak_ptr<CeService> ceService;
        std::shared_ptr<HostCardEmulationManager> manager =
            std::make_shared<HostCardEmulationManager>(nfcService, nciCeProxy, ceService);
        std::string type = NfcSdkCommon::BytesVecToHexString(data, size);
        AccessTokenID callerToken = 0;
        manager->UnRegHceCmdCallback(type, callerToken);
    }

    void FuzzUnRegAllCallback(const uint8_t* data, size_t size)
    {
        std::weak_ptr<NfcService> nfcService;
        std::weak_ptr<NCI::INciCeInterface> nciCeProxy;
        std::weak_ptr<CeService> ceService;
        std::shared_ptr<HostCardEmulationManager> manager =
            std::make_shared<HostCardEmulationManager>(nfcService, nciCeProxy, ceService);
        AccessTokenID callerToken = 0;
        manager->UnRegAllCallback(callerToken);
    }

    void FuzzSendHostApduData(const uint8_t* data, size_t size)
    {
        std::weak_ptr<NfcService> nfcService;
        std::weak_ptr<NCI::INciCeInterface> nciCeProxy;
        std::weak_ptr<CeService> ceService;
        std::shared_ptr<HostCardEmulationManager> manager =
            std::make_shared<HostCardEmulationManager>(nfcService, nciCeProxy, ceService);
        std::string hexCmdData = NfcSdkCommon::BytesVecToHexString(data, size);
        bool raw = data[0] % INT_TO_BOOL_DIVISOR;
        std::string hexRespData = NfcSdkCommon::BytesVecToHexString(data, size);
        AccessTokenID callerToken = 0;
        manager->SendHostApduData(hexCmdData, raw, hexRespData, callerToken);
    }

    void FuzzHandleQueueData(const uint8_t* data, size_t size)
    {
        std::weak_ptr<NfcService> nfcService;
        std::weak_ptr<NCI::INciCeInterface> nciCeProxy;
        std::weak_ptr<CeService> ceService;
        std::shared_ptr<HostCardEmulationManager> manager =
            std::make_shared<HostCardEmulationManager>(nfcService, nciCeProxy, ceService);
        manager->HandleQueueData();
    }

}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::FUZZER_THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    OHOS::FuzzOnHostCardEmulationDataNfcA(data, size);
    OHOS::FuzzOnCardEmulationActivated(data, size);
    OHOS::FuzzOnCardEmulationDeactivated(data, size);
    OHOS::FuzzRegHceCmdCallback(data, size);
    OHOS::FuzzUnRegHceCmdCallback(data, size);
    OHOS::FuzzUnRegAllCallback(data, size);
    OHOS::FuzzSendHostApduData(data, size);
    OHOS::FuzzHandleQueueData(data, size);
    return 0;
}
