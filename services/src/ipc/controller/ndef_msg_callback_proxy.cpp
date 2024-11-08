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

#include "ndef_msg_callback_proxy.h"

#include "nfc_service_ipc_interface_code.h"
#include "loghelper.h"

namespace OHOS {
namespace NFC {
NdefMsgCallbackProxy::NdefMsgCallbackProxy(const sptr<IRemoteObject> &remote)
    : IRemoteProxy<INdefMsgCallback>(remote)
{}

bool NdefMsgCallbackProxy::OnNdefMsgDiscovered(const std::string &tagUid, const std::string &ndef, int ndefMsgType)
{
    DebugLog("NdefMsgCallbackProxy::OnNdefMsgDiscovered");
    MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DebugLog("NdefMsgCallbackProxy::OnNdefMsgDiscovered, Write interface token error");
        return false;
    }
    data.WriteInt32(0);
    data.WriteString(tagUid);
    data.WriteString(ndef);
    data.WriteInt32(ndefMsgType);

    int error = Remote()->SendRequest(static_cast<uint32_t>(NfcServiceIpcInterfaceCode::COMMAND_ON_NDEF_MSG_NOTIFY),
        data, reply, option);
    if (error != ERR_NONE) {
        ErrorLog("NdefMsgCallbackProxy::OnNdefMsgDiscovered, Set Attr %{public}d error: %{public}d",
            NfcServiceIpcInterfaceCode::COMMAND_ON_NDEF_MSG_NOTIFY, error);
        return false;
    }
    bool res = reply.ReadBool();
    if (!res) {
        InfoLog("NdefMsgCallbackProxy::OnNdefMsgDiscovered, COMMAND_ON_NDEF_MSG_NOTIFY reply false");
        return false;
    }
    return true;
}
}  // namespace NFC
}  // namespace OHOS