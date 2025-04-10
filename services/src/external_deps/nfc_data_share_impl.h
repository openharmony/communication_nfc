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
#ifndef NFC_DATA_SHARE_IMPL_H
#define NFC_DATA_SHARE_IMPL_H
#include <singleton.h>
#include "datashare_helper.h"
#include "nfc_sdk_common.h"
#include "uri.h"

namespace OHOS {
namespace NFC {
const std::string NFC_DATA_COLUMN_KEYWORD = "KEYWORD";
const std::string NFC_DATA_COLUMN_VALUE = "VALUE";

class NfcDataShareImpl : public DelayedSingleton<NfcDataShareImpl> {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"nfc.INfcState");
    NfcDataShareImpl();
    ~NfcDataShareImpl();

    KITS::ErrorCode GetValue(Uri &uri, const std::string &column, int32_t &value);
    KITS::ErrorCode SetValue(Uri &uri, const std::string &column, int &value);
    std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper();

private:
    std::mutex mutex_ {};
    sptr<IRemoteObject> remoteObj_;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper_;
};

class INfcState : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"nfc.INfcState");
};
} // NFC
} // OHOS
#endif // NFC_DATA_SHARE_IMPL_H