/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "nfc_basic_proxy.h"

#include "loghelper.h"

namespace OHOS {
namespace NFC {
int NfcBasicProxy::SendRequestExpectReplyStringAndStatusCode(uint32_t cmd,
    MessageParcel& data, MessageParcel& reply, MessageOption& option, std::string& result)
{
    int ret = remoteObj_->SendRequest(cmd, data, reply, option);
    if (ret == ERR_NONE) {
        result = reply.ReadString();
    }
    InfoLog("SendRequestExpectReplyStringAndStatusCode, cmd %{public}d, ret %{public}d", cmd, ret);
    return ret;
}

int NfcBasicProxy::SendRequestExpectReplyIntAndStatusCode(uint32_t cmd,
    MessageParcel& data, MessageParcel& reply, MessageOption& option, int& result)
{
    int ret = remoteObj_->SendRequest(cmd, data, reply, option);
    if (ret == ERR_NONE) {
        result = reply.ReadInt32();
    }
    InfoLog("SendRequestExpectReplyIntAndStatusCode, cmd %{public}d, ret %{public}d, result %{public}d",
        cmd, ret, result);
    return ret;
}

int NfcBasicProxy::SendRequestExpectReplyBoolAndStatusCode(uint32_t cmd,
    MessageParcel& data, MessageParcel& reply, MessageOption& option, bool& result)
{
    int32_t ret = remoteObj_->SendRequest(cmd, data, reply, option);
    if (ret == ERR_NONE) {
        result = reply.ReadBool();
    }
    InfoLog("SendRequestExpectReplyBoolAndStatusCode, cmd %{public}d, ret %{public}d, result %{public}d",
        cmd, ret, result);
    return ret;
}

int NfcBasicProxy::SendRequestExpectReplyNoneAndStatusCode(uint32_t cmd,
    MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    int32_t ret = remoteObj_->SendRequest(cmd, data, reply, option);
    InfoLog("SendRequestExpectReplyNoneAndStatusCode, cmd %{public}d, ret %{public}d", cmd, ret);
    return ret;
}

int NfcBasicProxy::SendRequestExpectReplyInt(uint32_t cmd, MessageParcel& data, MessageOption& option, int& result)
{
    MessageParcel reply;
    int ret = remoteObj_->SendRequest(cmd, data, reply, option);
    if (ret == ERR_NONE) {
        result = reply.ReadInt32();
    }
    InfoLog("SendRequestExpectReplyInt, cmd %{public}d, ret %{public}d, reply %{public}d", cmd, ret, result);
    return ret;
}

int NfcBasicProxy::SendRequestExpectReplyBool(uint32_t cmd, MessageParcel& data, MessageOption& option, bool& result)
{
    MessageParcel reply;
    int32_t ret = remoteObj_->SendRequest(cmd, data, reply, option);
    if (ret == ERR_NONE) {
        result = reply.ReadBool();
    }
    InfoLog("SendRequestExpectReplyBool, cmd %{public}d, ret %{public}d, reply %{public}d", cmd, ret, result);
    return ret;
}

int NfcBasicProxy::SendRequestExpectReplyNone(uint32_t cmd, MessageParcel& data, MessageOption& option)
{
    MessageParcel reply;
    int32_t ret = remoteObj_->SendRequest(cmd, data, reply, option);
    InfoLog("SendRequestExpectReplyNone, cmd %{public}d, ret %{public}d", cmd, ret);
    return ret;
}
}  // namespace NFC
}  // namespace OHOS
