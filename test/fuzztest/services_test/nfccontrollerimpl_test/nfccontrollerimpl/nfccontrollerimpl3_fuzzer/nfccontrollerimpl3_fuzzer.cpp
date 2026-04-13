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
#include "nfccontrollerimpl_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "nfc_controller_impl.h"
#include "nfc_service.h"
#include "nfc_sdk_common.h"
#include "nfc_service_ipc_interface_code.h"
#include <securec.h>
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    using namespace OHOS::NFC;

    constexpr const auto FUZZER_THRESHOLD = 4;

    void ConvertToUint32s(const uint8_t* ptr, uint32_t* outPara, uint16_t outParaLen)
    {
        for (uint16_t i = 0 ; i < outParaLen ; i++) {
            // 4 uint8s compose 1 uint32 , 8 16 24 is bit operation, 2 3 4 are array subscripts.
            outPara[i] = (ptr[i * 4] << 24) | (ptr[(i * 4) + 1 ] << 16) | (ptr[(i * 4) + 2] << 8) | (ptr[(i * 4) + 3]);
        }
    }

    void FuzzDump(const uint8_t* data, size_t size)
    {
        FuzzedDataProvider fdp(data, size);
        int32_t fd = fdp.ConsumeIntegral<int32_t>();
        std::vector<std::u16string> args;
        std::shared_ptr<NfcService> service = nullptr;
        std::shared_ptr<NfcControllerImpl> nfcControllerImpl = std::make_shared<NfcControllerImpl>(service);
        nfcControllerImpl->Dump(fd, args);
    }

    void FuzzNotifyEventStatus(const uint8_t* data, size_t size)
    {
        FuzzedDataProvider fdp(data, size);
        int eventType = fdp.ConsumeIntegral<int32_t>();
        int arg1 = fdp.ConsumeIntegral<int32_t>();
        std::string arg2 = "";
        std::shared_ptr<NfcService> service = std::make_shared<NfcService>();
        std::shared_ptr<NfcControllerImpl> nfcControllerImpl = std::make_shared<NfcControllerImpl>(service);
        nfcControllerImpl->NotifyEventStatus(eventType, arg1, arg2);
        std::shared_ptr<NfcService> service1 = nullptr;
        std::shared_ptr<NfcControllerImpl> nfcControllerImpl1 = std::make_shared<NfcControllerImpl>(service1);
        nfcControllerImpl1->NotifyEventStatus(eventType, arg1, arg2);
    }

    void FuzzRestartNfc(const uint8_t* data, size_t size)
    {
        std::shared_ptr<NfcService> service = std::make_shared<NfcService>();
        std::shared_ptr<NfcControllerImpl> nfcControllerImpl = std::make_shared<NfcControllerImpl>(service);
        nfcControllerImpl->RestartNfc();
        std::shared_ptr<NfcService> service1 = nullptr;
        std::shared_ptr<NfcControllerImpl> nfcControllerImpl1 = std::make_shared<NfcControllerImpl>(service1);
        nfcControllerImpl1->RestartNfc();
    }

    void FuzzGetTagServiceIface(const uint8_t* data, size_t size)
    {
        std::shared_ptr<NfcService> service = std::make_shared<NfcService>();
        std::shared_ptr<NfcControllerImpl> nfcControllerImpl = std::make_shared<NfcControllerImpl>(service);
        sptr<IRemoteObject> iRemoteObject = nullptr;
        nfcControllerImpl->GetTagServiceIface(iRemoteObject);
        std::shared_ptr<NfcService> service1 = nullptr;
        std::shared_ptr<NfcControllerImpl> nfcControllerImpl1 = std::make_shared<NfcControllerImpl>(service1);
        nfcControllerImpl1->GetTagServiceIface(iRemoteObject);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::FUZZER_THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    OHOS::FuzzDump(data, size);
    OHOS::FuzzNotifyEventStatus(data, size);
    OHOS::FuzzRestartNfc(data, size);
    OHOS::FuzzGetTagServiceIface(data, size);

    return 0;
}
