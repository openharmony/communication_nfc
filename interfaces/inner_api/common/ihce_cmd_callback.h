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

#ifndef OHOS_I_NFC_HCE_CMD_H
#define OHOS_I_NFC_HCE_CMD_H

#include <string>
#include <string_ex.h>
#include <vector>
#include <iremote_broker.h>

#include "message_parcel.h"
#include "message_option.h"

namespace OHOS {
namespace NFC {
namespace KITS {
class IHceCmdCallback : public IRemoteBroker {
public:
    /**
     * @brief  send apdu data to js service
     * @param  data: data send to js service
     * @return void
     */
    virtual void OnCeApduData(const std::vector<uint8_t> &data) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.nfc.kits.IHceCmdCallback");
};
} // namespace KITS
} // namespace NFC
} // namespace OHOS
#endif
