/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#ifndef NDEF_BT_SSP_DATA_PARSER_H
#define NDEF_BT_SSP_DATA_PARSER_H

#include <string>

namespace OHOS {
namespace NFC {
class BtOobData {
public:
    bool isValid_ = false;
    std::string name_;
    std::string oobData_ = "";
    std::string uuids_ = "";

    std::string macAddress_ = "";
    std::string vendorSerialNum_ = "";
    std::string vendorPayload_ = "";
};

class NdefBtOobDataParser {
public:
    NdefBtOobDataParser();
    ~NdefBtOobDataParser() {}
    static std::shared_ptr<BtOobData> CheckBtRecord(const std::string& msg);

private:
    static std::shared_ptr<BtOobData> ParseBtOobRecord(const std::string& payload);
    static std::shared_ptr<BtOobData> ParseBleOobRecord(const std::string& payload);
    static std::string GetUuidFromPayload(const std::string& payload, uint32_t& offset, uint32_t type, uint32_t len);
    static std::string GetDataFromPayload(const std::string& payload, uint32_t& offset, uint32_t datalen);
    static std::string GetBtMacFromPayload(const std::string& payload, uint32_t& offset);

private:
};
} // namespace NFC
} // namespace OHOS
#endif // NDEF_BT_OOB_DATA_PARSER_H