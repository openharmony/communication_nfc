/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "ncitagproxy_fuzz.h"

#include <cstddef>
#include <cstdint>

#include "nci_tag_proxy.h"
#include "inci_tag_interface.h"
#include "nfc_sdk_common.h"
#include "nfc_service_ipc_interface_code.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    using namespace OHOS::NFC::NCI;
    using namespace OHOS::NFC::KITS;

    constexpr const auto FUZZER_INT32_THRESHOLD = 4;  // 4 uint8 form 1 uint32
    constexpr const auto FUZZER_2INT32_THRESHOLD = 8;  // 8 uint8 form 2 uint32
    constexpr const auto FUZZER_3INT32_THRESHOLD = 12;  // 12 uint8 form 3 uint32

    void ConvertToUint32s(const uint8_t* ptr, uint32_t* outPara, uint16_t outParaLen)
    {
        for (uint16_t i = 0 ; i < outParaLen ; i++) {
            // 4 uint8s compose 1 uint32 , 8 16 24 is bit operation, 2 3 4 are array subscripts.
            outPara[i] = (ptr[i * 4] << 24) | (ptr[(i * 4) + 1 ] << 16) | (ptr[(i * 4) + 2] << 8) | (ptr[(i * 4) + 3]);
        }
    }

    void FuzzStartFieldOnChecking(const uint8_t* data, size_t size)
    {
        if (size < OHOS::FUZZER_2INT32_THRESHOLD) {
            return;
        }
        std::shared_ptr<NciTagProxy> nciTagProxy = std::make_shared<NciTagProxy>();
        uint32_t intArray[2];  // need 2 int32
        ConvertToUint32s(data, intArray, 2);  // need 2 int32
        uint32_t tagDiscId = intArray[0];
        uint32_t delayedMs = intArray[1];
        nciTagProxy->StartFieldOnChecking(tagDiscId, delayedMs);
    }

    void FuzzSetTimeout(const uint8_t* data, size_t size)
    {
        if (size < OHOS::FUZZER_3INT32_THRESHOLD) {
            return;
        }
        std::shared_ptr<NciTagProxy> nciTagProxy = std::make_shared<NciTagProxy>();
        uint32_t intArray[3];
        ConvertToUint32s(data, intArray, 3);  // need 3 uint32_t
        uint32_t tagDiscId = intArray[0];
        uint32_t timeout = intArray[1];
        uint32_t technology = intArray[2];  // need 3 uint32_t
        nciTagProxy->SetTimeout(tagDiscId, timeout, technology);
    }

    void FuzzResetTimeout(const uint8_t* data, size_t size)
    {
        std::shared_ptr<NciTagProxy> nciTagProxy = std::make_shared<NciTagProxy>();
        uint32_t tagDiscId[1];
        ConvertToUint32s(data, tagDiscId, 1);
        nciTagProxy->ResetTimeout(tagDiscId[0]);
    }

    void FuzzGetTechMaskFromTechList(const uint8_t* data, size_t size)
    {
        FuzzedDataProvider fdp(data, size);
        uint16_t Len = fdp.ConsumeIntegral<uint16_t>();
        std::shared_ptr<NciTagProxy> nciTagProxy = std::make_shared<NciTagProxy>();
        uint32_t discTechArray[int32Len];
        for (int i = 0; i < Len; i++) {
            discTechArray[i] = fdp.ConsumeIntegral<uint32_t>();
        }
        std::vector<uint32_t> discTech;
        for (uint32_t i = 0; i < int32Len; i++) {
            discTech.push_back(discTechArray[i]);
        }
        nciTagProxy->GetTechMaskFromTechList(discTech);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::FUZZER_INT32_THRESHOLD) {
        return 0;
    }

    /* Run your code on data */ 
    OHOS::FuzzStartFieldOnChecking(data, size);
    OHOS::FuzzSetTimeout(data, size);
    OHOS::FuzzResetTimeout(data, size);
    OHOS::FuzzGetTechMaskFromTechList(data, size);
    return 0;
}