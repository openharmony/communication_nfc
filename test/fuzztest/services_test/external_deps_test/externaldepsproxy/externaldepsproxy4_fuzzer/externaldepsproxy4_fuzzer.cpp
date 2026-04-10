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
    constexpr const auto FUZZER_THRESHOLD_FOUR = 16;
    constexpr const auto FUZZER_THRESHOLD_TWO = 8;

    void ConvertToUint32s(const uint8_t* ptr, uint32_t* outPara, uint16_t outParaLen)
    {
        for (uint16_t i = 0 ; i < outParaLen ; i++) {
            // 4 uint8s compose 1 uint32 , 8 16 24 is bit operation, 2 3 4 are array subscripts.
            outPara[i] = (ptr[i * 4] << 24) | (ptr[(i * 4) + 1 ] << 16) | (ptr[(i * 4) + 2] << 8) | (ptr[(i * 4) + 3]);
        }
    }

    void FuzzWriteDefaultPaymentAppChangeHiSysEvent(const uint8_t* data, size_t size)
    {
        uint32_t timeOutArray[1];
        ConvertToUint32s(data, timeOutArray, 1);
        std::string oldAppPackageName = NfcSdkCommon::IntToHexString(timeOutArray[0]);
        std::string newAppPackageName = NfcSdkCommon::BytesVecToHexString(data, size);
        ExternalDepsProxy::GetInstance().WriteDefaultPaymentAppChangeHiSysEvent(
            oldAppPackageName, newAppPackageName);
    }

    void FuzzWriteTagFoundHiSysEvent(const uint8_t* data, size_t size)
    {
        std::vector<int> discTechList;
        uint32_t timeOutArray[1];
        ConvertToUint32s(data, timeOutArray, 1);
        discTechList.push_back(timeOutArray[0]);
        ExternalDepsProxy::GetInstance().WriteTagFoundHiSysEvent(discTechList);
    }

    void FuzzWritePassiveListenHiSysEvent(const uint8_t* data, size_t size)
    {
        if (size < OHOS::NFC::FUZZER_THRESHOLD_TWO) {
            return;
        }
        uint32_t timeOutArray[2]; // need 2 int
        ConvertToUint32s(data, timeOutArray, 2); // need 2 int
        int requestCnt = timeOutArray[0];
        int failCnt = timeOutArray[1];
        ExternalDepsProxy::GetInstance().WritePassiveListenHiSysEvent(requestCnt, failCnt);
    }

    void FuzzWriteFirmwareUpdateHiSysEvent(const uint8_t* data, size_t size)
    {
        if (size < OHOS::NFC::FUZZER_THRESHOLD_TWO) {
            return;
        }
        uint32_t timeOutArray[2]; // need 2 int
        ConvertToUint32s(data, timeOutArray, 2); // need 2 int
        int requestCnt = timeOutArray[0];
        int failCnt = timeOutArray[1];
        ExternalDepsProxy::GetInstance().WriteFirmwareUpdateHiSysEvent(requestCnt, failCnt);
    }

    void FuzzIsGranted(const uint8_t* data, size_t size)
    {
        std::string permission = NfcSdkCommon::BytesVecToHexString(data, size);
        ExternalDepsProxy::GetInstance().IsGranted(permission);
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
    OHOS::NFC::FuzzWriteDefaultPaymentAppChangeHiSysEvent(data, size);
    OHOS::NFC::FuzzWriteTagFoundHiSysEvent(data, size);
    OHOS::NFC::FuzzWritePassiveListenHiSysEvent(data, size);
    OHOS::NFC::FuzzWriteFirmwareUpdateHiSysEvent(data, size);
    OHOS::NFC::FuzzIsGranted(data, size);
    return 0;
}
