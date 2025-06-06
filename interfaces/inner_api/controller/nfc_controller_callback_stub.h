/*
* Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef OHOS_NFC_CONTROLLER_CALLBACK_STUB_H
#define OHOS_NFC_CONTROLLER_CALLBACK_STUB_H

#include <shared_mutex>

#include "nfc_sdk_common.h"
#include "infc_controller_callback.h"
#include "iremote_object.h"
#include "iremote_stub.h"


namespace OHOS {
namespace NFC {
class NfcControllerCallBackStub : public IRemoteStub<INfcControllerCallback> {
public:
    NfcControllerCallBackStub();
    virtual ~NfcControllerCallBackStub();
    static NfcControllerCallBackStub& GetInstance();
    KITS::ErrorCode RegisterCallBack(const sptr<INfcControllerCallback> &callBack);

    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    void OnNfcStateChanged(int nfcRfState) override;
    int RemoteNfcStateChanged(MessageParcel &data, MessageParcel &reply);
    sptr<INfcControllerCallback> callback_;
    std::shared_mutex callbackMutex;
    bool mRemoteDied;
};
}  // namespace NFC
}  // namespace OHOS
#endif