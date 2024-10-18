/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef NFC_PARAM_UTIL_H
#define NFC_PARAM_UTIL_H

#include <string>

constexpr const char* NFC_SWITCH_STATE_PARAM_NAME = "persist.nfc.switch.state";
const int PROPERTY_VALUE_MAX = 16;
const int NFC_SWITCH_PARAM_LEN = 1;
const uint32_t DECIMAL_NOTATION = 10;

namespace OHOS {
namespace NFC {
class NfcParamUtil {
public:
    static void UpdateNfcStateToParam(int newState);
    static int GetNfcStateFromParam();
};
}  // namespace NFC
}  // namespace OHOS
#endif // NFC_PARAM_UTIL_H