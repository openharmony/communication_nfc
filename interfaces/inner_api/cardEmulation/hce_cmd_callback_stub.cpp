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

#include "hce_cmd_callback_stub.h"

#include "nfc_sdk_common.h"
#include "nfc_service_ipc_interface_code.h"
#include "loghelper.h"

namespace OHOS {
namespace NFC {
namespace HCE {
HceCmdCallbackStub::HceCmdCallbackStub() : callback_(nullptr), mRemoteDied(false)
{
}

HceCmdCallbackStub::~HceCmdCallbackStub()
{
}

HceCmdCallbackStub &HceCmdCallbackStub::GetInstance()
{
    static HceCmdCallbackStub hceCmdCallbackStub;
    return hceCmdCallbackStub;
}

KITS::ErrorCode HceCmdCallbackStub::RegHceCmdCallback(const sptr<IHceCmdCallback> &callback)
{
    DebugLog("HceCmdCallbackStub RegisterCallBack");
    std::unique_lock<std::shared_mutex> guard(callbackMutex);
    if (callback == nullptr) {
        ErrorLog("HceCmdCallbackStub:callBack is nullptr!");
        callback_ = callback;
        return KITS::ERR_NFC_PARAMETERS;
    }
    callback_ = callback;
    return KITS::ERR_NONE;
}

KITS::ErrorCode HceCmdCallbackStub::UnRegHceCmdCallback(const sptr<IHceCmdCallback> &callback)
{
    DebugLog("HceCmdCallbackStub UnRegisterCallBack");
    if (callback_ == nullptr) {
        InfoLog("HceCmdCallbackStub:Callback_ has unregistered!");
        return KITS::ERR_NFC_PARAMETERS;
    }
    std::unique_lock<std::shared_mutex> guard(callbackMutex);
    callback_ = nullptr;
    return KITS::ERR_NONE;
}

int HceCmdCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DebugLog("HceCmdCallbackStub::OnRemoteRequest,code = %{public}d", code);
    if (mRemoteDied) {
        return KITS::ERR_NFC_STATE_UNBIND;
    }
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ErrorLog("nfc callback stub token verification error");
        return KITS::ERR_NFC_PARAMETERS;
    }
    int exception = data.ReadInt32();
    if (exception) {
        ErrorLog("HceCmdCallbackStub::OnRemoteRequest, got exception: (%{public}d))", exception);
        return exception;
    }
    int ret = KITS::ERR_NFC_STATE_UNBIND;
    switch (code) {
        case static_cast<uint32_t>(NfcServiceIpcInterfaceCode::COMMAND_ON_CE_APDU_DATA): {
            ret = RemoteOnCeApduData(data, reply);
            break;
        }
        default: {
            ret = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
        }
    }
    return ret;
}
int HceCmdCallbackStub::RemoteOnCeApduData(MessageParcel &data, MessageParcel &reply)
{
    InfoLog("run %{public}zu datasize ", data.GetRawDataSize());
    std::vector<uint8_t> apduData;
    data.ReadUInt8Vector(&apduData);
    std::unique_lock<std::shared_mutex> guard(callbackMutex);
    OnCeApduData(apduData);
    reply.WriteInt32(KITS::ERR_NONE); /* Reply 0 to indicate that no exception occurs. */
    return KITS::ERR_NONE;
}
void HceCmdCallbackStub::OnCeApduData(const std::vector<uint8_t> &data)
{
    if (callback_) {
        DebugLog("HceCmdCallbackStub callback_");
        callback_->OnCeApduData(data);
    }
}
}
}
}
