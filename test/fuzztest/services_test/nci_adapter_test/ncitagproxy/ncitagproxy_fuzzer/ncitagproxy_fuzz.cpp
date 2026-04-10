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
#include "ndeftag_fuzzer/FuzzedDataProvider.h"

namespace OHOS {
    using namespace OHOS::NFC::NCI;
    using namespace OHOS::NFC::KITS;

    constexpr const auto FUZZER_INT32_THRESHOLD = 4;  // 4 uint8 form 1 uint32

    void ConvertToUint32s(const uint8_t* ptr, uint32_t* outPara, uint16_t outParaLen)
    {
        for (uint16_t i = 0 ; i < outParaLen ; i++) {
            // 4 uint8s compose 1 uint32 , 8 16 24 is bit operation, 2 3 4 are array subscripts.
            outPara[i] = (ptr[i * 4] << 24) | (ptr[(i * 4) + 1 ] << 16) | (ptr[(i * 4) + 2] << 8) | (ptr[(i * 4) + 3]);
        }
    }

    void FuzzSetTagListener(const uint8_t* data, size_t size)
    {
        std::shared_ptr<INciTagInterface::ITagListener> listener = nullptr;
        std::shared_ptr<NciTagProxy> nciTagProxy = std::make_shared<NciTagProxy>();
        nciTagProxy->SetTagListener(listener);
    }

    void FuzzGetTechList(const uint8_t* data, size_t size)
    {
        std::shared_ptr<NciTagProxy> nciTagProxy = std::make_shared<NciTagProxy>();
        uint32_t tagDiscId[1];
        ConvertToUint32s(data, tagDiscId, 1);
        nciTagProxy->GetTechList(tagDiscId[0]);
    }

    void FuzzGetConnectedTech(const uint8_t* data, size_t size)
    {
        std::shared_ptr<NciTagProxy> nciTagProxy = std::make_shared<NciTagProxy>();
        uint32_t tagDiscId[1];
        ConvertToUint32s(data, tagDiscId, 1);
        nciTagProxy->GetConnectedTech(tagDiscId[0]);
    }

    void FuzzGetTechExtrasData(const uint8_t* data, size_t size)
    {
        std::shared_ptr<NciTagProxy> nciTagProxy = std::make_shared<NciTagProxy>();
        uint32_t tagDiscId[1];
        ConvertToUint32s(data, tagDiscId, 1);
        nciTagProxy->GetTechExtrasData(tagDiscId[0]);
    }

    void FuzzGetTagUid(const uint8_t* data, size_t size)
    {
        std::shared_ptr<NciTagProxy> nciTagProxy = std::make_shared<NciTagProxy>();
        uint32_t tagDiscId[1];
        ConvertToUint32s(data, tagDiscId, 1);
        nciTagProxy->GetTagUid(tagDiscId[0]);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::FUZZER_INT32_THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    OHOS::FuzzSetTagListener(data, size);
    OHOS::FuzzGetTechList(data, size);
    OHOS::FuzzGetConnectedTech(data, size);
    OHOS::FuzzGetTechExtrasData(data, size);
    OHOS::FuzzGetTagUid(data, size);
    return 0;
}