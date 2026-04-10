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

    void ConvertToUint32s(const uint8_t* ptr, uint32_t* outPara, uint16_t outParaLen)
    {
        for (uint16_t i = 0 ; i < outParaLen ; i++) {
            // 4 uint8s compose 1 uint32 , 8 16 24 is bit operation, 2 3 4 are array subscripts.
            outPara[i] = (ptr[i * 4] << 24) | (ptr[(i * 4) + 1 ] << 16) | (ptr[(i * 4) + 2] << 8) | (ptr[(i * 4) + 3]);
        }
    }

    void FuzzUpdateNfcState(const uint8_t* data, size_t size)
    {
        uint32_t timeOutArray[1];
        ConvertToUint32s(data, timeOutArray, 1);
        int newState = timeOutArray[0];
        ExternalDepsProxy::GetInstance().UpdateNfcState(newState);
    }

    void FuzzPublishNfcStateChanged(const uint8_t* data, size_t size)
    {
        uint32_t timeOutArray[1];
        ConvertToUint32s(data, timeOutArray, 1);
        int newState = timeOutArray[0];
        ExternalDepsProxy::GetInstance().PublishNfcStateChanged(newState);
    }

    void FuzzPublishNfcFieldStateChanged(const uint8_t* data, size_t size)
    {
        // Remainder 2 to obtain random bool
        bool isFieldOn = (data[0] % 2) == 1;
        ExternalDepsProxy::GetInstance().PublishNfcFieldStateChanged(isFieldOn);
    }

    void FuzzWriteNfcFailedHiSysEvent(const uint8_t* data, size_t size)
    {
        MainErrorCode mainErrorCode = static_cast<MainErrorCode>(data[0]);
        SubErrorCode subErrorCode = static_cast<SubErrorCode>(data[1]);
        ExternalDepsProxy::GetInstance().WriteNfcFailedHiSysEvent(mainErrorCode, subErrorCode);
    }

    void FuzzWriteOpenAndCloseHiSysEvent(const uint8_t* data, size_t size)
    {
        if (size < OHOS::NFC::FUZZER_THRESHOLD_FOUR) {
            return;
        }
        // 4 ints required
        uint32_t timeOutArray[4]; // need 4 int
        ConvertToUint32s(data, timeOutArray, 4); // need 4 int
        int openRequestCnt = timeOutArray[0];
        int openFailCnt = timeOutArray[1];
        int closeRequestCnt = timeOutArray[2]; // 3th int, array index 2
        int closeFailCnt = timeOutArray[3]; // 4th int, array index 3
        ExternalDepsProxy::GetInstance().WriteOpenAndCloseHiSysEvent(
            openRequestCnt, openFailCnt, closeRequestCnt, closeFailCnt);
    }

    void FuzzWriteHceSwipeResultHiSysEvent(const uint8_t* data, size_t size)
    {
        uint32_t timeOutArray[1];
        ConvertToUint32s(data, timeOutArray, 1);
        std::string appPackageName = NfcSdkCommon::BytesVecToHexString(data, size);
        int hceSwipeCnt = timeOutArray[0];
        ExternalDepsProxy::GetInstance().WriteHceSwipeResultHiSysEvent(appPackageName, hceSwipeCnt);
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
    OHOS::NFC::FuzzPublishNfcStateChanged(data, size);
    OHOS::NFC::FuzzPublishNfcFieldStateChanged(data, size);
    OHOS::NFC::FuzzWriteNfcFailedHiSysEvent(data, size);
    OHOS::NFC::FuzzWriteOpenAndCloseHiSysEvent(data, size);
    OHOS::NFC::FuzzWriteHceSwipeResultHiSysEvent(data, size);
    return 0;
}
