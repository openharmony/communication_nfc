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

    void FuzzHandleAppAddOrChangedEvent(const uint8_t* data, size_t size)
    {
        AAFwk::Want want;
        std::string action = NfcSdkCommon::BytesVecToHexString(data, size);
        want.SetAction(action);
        uint32_t timeOutArray[1];
        ConvertToUint32s(data, timeOutArray, 1);
        std::shared_ptr<EventFwk::CommonEventData> eventData = std::make_shared<EventFwk::CommonEventData>();
        eventData->SetCode(timeOutArray[0]);
        eventData->SetWant(want);
        ExternalDepsProxy::GetInstance().HandleAppAddOrChangedEvent(eventData);
    }

    void FuzzHandleAppRemovedEvent(const uint8_t* data, size_t size)
    {
        AAFwk::Want want;
        AppExecFwk::ElementName element;
        std::string bundleName = NfcSdkCommon::BytesVecToHexString(data, size);
        element.SetBundleName(bundleName);
        want.SetElement(element);
        uint32_t timeOutArray[1];
        ConvertToUint32s(data, timeOutArray, 1);
        std::shared_ptr<EventFwk::CommonEventData> eventData = std::make_shared<EventFwk::CommonEventData>();
        eventData->SetCode(timeOutArray[0]);
        eventData->SetWant(want);
        ExternalDepsProxy::GetInstance().HandleAppRemovedEvent(eventData);
    }

    void FuzzGetDispatchTagAppsByTech(const uint8_t* data, size_t size)
    {
        std::vector<int> discTechList;
        uint32_t timeOutArray[1];
        ConvertToUint32s(data, timeOutArray, 1);
        discTechList.push_back(timeOutArray[0]);
        ExternalDepsProxy::GetInstance().GetDispatchTagAppsByTech(discTechList);
    }

    void FuzzNfcDataGetValue(const uint8_t* data, size_t size)
    {
        Uri nfcEnableUri(KITS::NFC_DATA_URI);
        uint32_t timeOutArray[1];
        ConvertToUint32s(data, timeOutArray, 1);
        std::string column = NfcSdkCommon::BytesVecToHexString(data, size);
        int32_t value = timeOutArray[0];
        ExternalDepsProxy::GetInstance().NfcDataGetValue(nfcEnableUri, column, value);
    }

    void FuzzNfcDataSetValue(const uint8_t* data, size_t size)
    {
        Uri nfcEnableUri(KITS::NFC_DATA_URI);
        uint32_t timeOutArray[1];
        ConvertToUint32s(data, timeOutArray, 1);
        std::string column = NfcSdkCommon::BytesVecToHexString(data, size);
        int32_t value = timeOutArray[0];
        ExternalDepsProxy::GetInstance().NfcDataSetValue(nfcEnableUri, column, value);
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
    OHOS::NFC::FuzzHandleAppAddOrChangedEvent(data, size);
    OHOS::NFC::FuzzHandleAppRemovedEvent(data, size);
    OHOS::NFC::FuzzGetDispatchTagAppsByTech(data, size);
    OHOS::NFC::FuzzNfcDataGetValue(data, size);
    OHOS::NFC::FuzzNfcDataSetValue(data, size);
    return 0;
}
