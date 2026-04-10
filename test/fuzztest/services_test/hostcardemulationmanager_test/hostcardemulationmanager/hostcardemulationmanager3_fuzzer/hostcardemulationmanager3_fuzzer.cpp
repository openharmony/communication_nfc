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
#include "nci_native_selector.h"
#include "nfc_sdk_common.h"
#include "nfc_service_ipc_interface_code.h"
#include <securec.h>

namespace OHOS {
    using namespace OHOS::NFC::NCI;
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

    const uint8_t *g_baseFuzzData = nullptr;
    size_t g_baseFuzzSize = 0;
    size_t g_baseFuzzPos = 0;

    void ConvertToUint32s(const uint8_t* ptr, uint32_t* outPara, uint16_t outParaLen)
    {
        for (uint16_t i = 0 ; i < outParaLen ; i++) {
            // 4 uint8s compose 1 uint32 , 8 16 24 is bit operation, 2 3 4 are array subscripts.
            outPara[i] = (ptr[i * 4] << 24) | (ptr[(i * 4) + 1 ] << 16) | (ptr[(i * 4) + 2] << 8) | (ptr[(i * 4) + 3]);
        }
    }

    template <class T> T GetData()
    {
        T object{};
        size_t objectSize = sizeof(object);
        if (g_baseFuzzData == nullptr || objectSize > g_baseFuzzSize - g_baseFuzzPos) {
            return object;
        }
        errno_t ret = memcpy_s(&object, objectSize, g_baseFuzzData + g_baseFuzzPos, objectSize);
        if (ret != EOK) {
            return {};
        }
        g_baseFuzzPos += objectSize;
        return object;
    }

    void FuzzSendHostApduData1(const uint8_t* data, size_t size)
    {
        std::shared_ptr<NfcService> nfcService = std::make_shared<NfcService>();
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

    void FuzzOnAbilityDisconnectDone(const uint8_t* data, size_t size)
    {
        g_baseFuzzData = data;
        g_baseFuzzSize = size;
        g_baseFuzzPos = 0;

        AppExecFwk::ElementName element;
        int resultCode = GetData<int>();
        std::shared_ptr<NfcAbilityConnectionCallback> callback = std::make_shared<NfcAbilityConnectionCallback>();
        callback->OnAbilityDisconnectDone(element, resultCode);
    }

    void FuzzSetHceManager(const uint8_t* data, size_t size)
    {
        std::weak_ptr<HostCardEmulationManager> hceManager;
        std::shared_ptr<NfcAbilityConnectionCallback> callback = std::make_shared<NfcAbilityConnectionCallback>();
        callback->SetHceManager(hceManager);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::FUZZER_THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    OHOS::FuzzSendHostApduData1(data, size);
    OHOS::FuzzHandleQueueData(data, size);
    OHOS::FuzzOnAbilityDisconnectDone(data, size);
    OHOS::FuzzSetHceManager(data, size);
    return 0;
}
