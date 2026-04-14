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
#include "externaldepsproxy_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "access_token.h"
#include "nfc_sdk_common.h"
#include "nfc_service_ipc_interface_code.h"
#include "nfc_hisysevent.h"
#include "app_data_parser.h"
#include "external_deps_proxy.h"

namespace OHOS {
namespace NFC {
    using namespace OHOS::NFC::KITS;

    constexpr const auto FUZZER_THRESHOLD = 4;

    void ConvertToUint32s(const uint8_t* ptr, uint32_t* outPara, uint16_t outParaLen)
    {
        for (uint16_t i = 0 ; i < outParaLen ; i++) {
            // 4 uint8s compose 1 uint32 , 8 16 24 is bit operation, 2 3 4 are array subscripts.
            outPara[i] = (ptr[i * 4] << 24) | (ptr[(i * 4) + 1 ] << 16) | (ptr[(i * 4) + 2] << 8) | (ptr[(i * 4) + 3]);
        }
    }

    void FuzzNfcDataSetString(const uint8_t* data, size_t size)
    {
        uint32_t timeOutArray[1];
        ConvertToUint32s(data, timeOutArray, 1);
        std::string key = NfcSdkCommon::IntToHexString(timeOutArray[0]);
        std::string value = NfcSdkCommon::BytesVecToHexString(data, size);
        ExternalDepsProxy::GetInstance().NfcDataSetString(key, value);
    }

    void FuzzNfcDataGetString(const uint8_t* data, size_t size)
    {
        std::string key = NfcSdkCommon::BytesVecToHexString(data, size);
        ExternalDepsProxy::GetInstance().NfcDataGetString(key);
    }

    void FuzzNfcDataSetInt(const uint8_t* data, size_t size)
    {
        uint32_t timeOutArray[1];
        ConvertToUint32s(data, timeOutArray, 1);
        std::string key = NfcSdkCommon::IntToHexString(timeOutArray[0]);
        int value = timeOutArray[0];
        ExternalDepsProxy::GetInstance().NfcDataSetInt(key, value);
    }

    void FuzzNfcDataGetInt(const uint8_t* data, size_t size)
    {
        std::string key = NfcSdkCommon::BytesVecToHexString(data, size);
        ExternalDepsProxy::GetInstance().NfcDataGetInt(key);
    }

    void FuzzNfcDataDelete(const uint8_t* data, size_t size)
    {
        std::string key = NfcSdkCommon::BytesVecToHexString(data, size);
        ExternalDepsProxy::GetInstance().NfcDataDelete(key);
    }
} // namespace NFC
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::NFC::FUZZER_THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    OHOS::NFC::FuzzNfcDataSetString(data, size);
    OHOS::NFC::FuzzNfcDataGetString(data, size);
    OHOS::NFC::FuzzNfcDataSetInt(data, size);
    OHOS::NFC::FuzzNfcDataGetInt(data, size);
    OHOS::NFC::FuzzNfcDataDelete(data, size);
    return 0;
}
