/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "mifareclassictag_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "mifare_classic_tag.h"
#include "ndef_message.h"
#include "ndef_tag.h"
#include "nfca_tag.h"
#include "nfc_sdk_common.h"
#include "taginfo.h"
#include "tag_session_proxy.h"
#include <securec.h>
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    using namespace OHOS::NFC::KITS;

    constexpr const auto FUZZER_THRESHOLD = 4;
    constexpr const auto TEST_UID = "0102";
    constexpr const auto TEST_DISC_ID = 1;
    constexpr const auto TEST_SAK = 0x28;
    constexpr const auto TEST_ATQA = "0400";

    uint32_t ConvertToUint32(const uint8_t* ptr)
    {
        if (ptr == nullptr) {
            return 0;
        }

        // Shift the 0th number to the left by 24 bits, shift the 1st number to the left by 16 bits,
        // shift the 2nd number to the left by 8 bits, and not shift the 3rd number to the left
        return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | (ptr[3]);
    }

    std::shared_ptr<TagInfo> FuzzGetTagInfo()
    {
        std::vector<int> tagTechList;
        tagTechList.push_back(static_cast<int>(TagTechnology::NFC_MIFARE_CLASSIC_TECH));
        tagTechList.push_back(static_cast<int>(TagTechnology::NFC_A_TECH));

        std::vector<AppExecFwk::PacMap> tagTechExtras;
        AppExecFwk::PacMap mifareClassicExtrasData;
        AppExecFwk::PacMap nfcAExtrasData;
        nfcAExtrasData.PutIntValue(TagInfo::SAK, TEST_SAK);
        nfcAExtrasData.PutStringValue(TagInfo::ATQA, TEST_ATQA);
        tagTechExtras.push_back(mifareClassicExtrasData);
        tagTechExtras.push_back(nfcAExtrasData);

        std::string tagUid = TEST_UID;
        int tagRfDiscId = TEST_DISC_ID;
        std::shared_ptr<TagInfo> tagInfo = std::make_shared<TagInfo>(tagTechList,
                                                                     tagTechExtras,
                                                                     tagUid,
                                                                     tagRfDiscId,
                                                                     nullptr);
        return tagInfo;
    }

    void FuzzIncrementBlock(const uint8_t* data, size_t size)
    {
        std::shared_ptr<TagInfo> tagInfo = FuzzGetTagInfo();
        if (tagInfo == nullptr) {
            std::cout << "tagInfo is nullptr." << std::endl;
            return;
        }
        std::shared_ptr<MifareClassicTag> mifareClassisTag = MifareClassicTag::GetTag(tagInfo);
        FuzzedDataProvider fdp(data, size);
        int value = fdp.ConsumeIntegral<int>();
        uint32_t blockIndex = ConvertToUint32(data);
        mifareClassisTag->IncrementBlock(blockIndex, value);
    }

    void FuzzDecrementBlock(const uint8_t* data, size_t size)
    {
        std::shared_ptr<TagInfo> tagInfo = FuzzGetTagInfo();
        if (tagInfo == nullptr) {
            std::cout << "tagInfo is nullptr." << std::endl;
            return;
        }
        std::shared_ptr<MifareClassicTag> mifareClassisTag = MifareClassicTag::GetTag(tagInfo);
        FuzzedDataProvider fdp(data, size);
        int value = fdp.ConsumeIntegral<int>();
        uint32_t blockIndex = ConvertToUint32(data);
        mifareClassisTag->DecrementBlock(blockIndex, value);
    }
    
    void FuzzTransferToBlock(const uint8_t* data, size_t size)
    {
        std::shared_ptr<TagInfo> tagInfo = FuzzGetTagInfo();
        if (tagInfo == nullptr) {
            std::cout << "tagInfo is nullptr." << std::endl;
            return;
        }
        std::shared_ptr<MifareClassicTag> mifareClassisTag = MifareClassicTag::GetTag(tagInfo);
        uint32_t blockIndex = ConvertToUint32(data);
        mifareClassisTag->TransferToBlock(blockIndex);
    }
    
    void FuzzRestoreFromBlock(const uint8_t* data, size_t size)
    {
        std::shared_ptr<TagInfo> tagInfo = FuzzGetTagInfo();
        if (tagInfo == nullptr) {
            std::cout << "tagInfo is nullptr." << std::endl;
            return;
        }
        std::shared_ptr<MifareClassicTag> mifareClassisTag = MifareClassicTag::GetTag(tagInfo);
        uint32_t blockIndex = ConvertToUint32(data);
        mifareClassisTag->RestoreFromBlock(blockIndex);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::FUZZER_THRESHOLD) {
        return 0;
    }
    /* Run your code on data */
    OHOS::FuzzIncrementBlock(data, size);
    OHOS::FuzzDecrementBlock(data, size);
    OHOS::FuzzTransferToBlock(data, size);
    OHOS::FuzzRestoreFromBlock(data, size);
    return 0;
}
