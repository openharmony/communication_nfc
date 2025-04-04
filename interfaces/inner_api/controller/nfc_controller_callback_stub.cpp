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

#include "nfc_controller_callback_stub.h"

#include "nfc_sdk_common.h"
#include "nfc_service_ipc_interface_code.h"
#include "loghelper.h"

namespace OHOS {
namespace NFC {
NfcControllerCallBackStub::NfcControllerCallBackStub() : callback_(nullptr), mRemoteDied(false)
{}

NfcControllerCallBackStub::~NfcControllerCallBackStub()
{}

NfcControllerCallBackStub& NfcControllerCallBackStub::GetInstance()
{
    static NfcControllerCallBackStub nfcControllerCallBackStub;
    return nfcControllerCallBackStub;
}

void NfcControllerCallBackStub::OnNfcStateChanged(int nfcRfState)
{
    if (callback_) {
        DebugLog("NfcControllerCallBackStub callback_");
        callback_->OnNfcStateChanged(nfcRfState);
    }
}

int NfcControllerCallBackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DebugLog("NfcControllerCallBackStub::OnRemoteRequest,code = %{public}d", code);
    if (mRemoteDied) {
        return KITS::ERR_NFC_STATE_UNBIND;
    }
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ErrorLog("NfcControllerCallBackStub::OnRemoteRequest, nfc callback stub token verification error");
        return KITS::ERR_NFC_PARAMETERS;
    }
    int exception = data.ReadInt32();
    if (exception) {
        ErrorLog("NfcControllerCallBackStub::OnRemoteRequest, got exception: (%{public}d))", exception);
        return exception;
    }
    int ret = KITS::ERR_NFC_STATE_UNBIND;
    switch (code) {
        case static_cast<uint32_t>(NfcServiceIpcInterfaceCode::COMMAND_ON_NOTIFY): {
            ret = RemoteNfcStateChanged(data, reply);
            break;
        }
        default: {
            ret = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
        }
    }
    return ret;
}

KITS::ErrorCode NfcControllerCallBackStub::RegisterCallBack(const sptr<INfcControllerCallback> &callBack)
{
    DebugLog("NfcControllerCallBackStub RegisterCallBack");
    if (callback_ != nullptr) {
        ErrorLog("NfcControllerCallBackStub:Callback_ has registered!");
        return KITS::ERR_NFC_PARAMETERS;
    }
    std::unique_lock<std::shared_mutex> guard(callbackMutex);
    if (callBack == nullptr) {
        ErrorLog("RegisterUserCallBack:callBack is nullptr!");
        callback_ = callBack;
        return KITS::ERR_NFC_PARAMETERS;
    }
    callback_ = callBack;
    return KITS::ERR_NONE;
}

int NfcControllerCallBackStub::RemoteNfcStateChanged(MessageParcel &data, MessageParcel &reply)
{
    int state = data.ReadInt32();
    std::unique_lock<std::shared_mutex> guard(callbackMutex);
    InfoLog("callback state = %{public}d", state);
    OnNfcStateChanged(state);
    reply.WriteInt32(KITS::ERR_NONE); /* Reply 0 to indicate that no exception occurs. */
    return KITS::ERR_NONE;
}
}  // namespace NFC
}  // namespace OHOS