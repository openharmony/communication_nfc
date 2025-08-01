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
#include "basic_tag_session.h"
#include "loghelper.h"
#include "nfc_controller.h"
#include "nfc_sdk_common.h"
#include "tag_session_proxy.h"

namespace OHOS {
namespace NFC {
namespace KITS {
BasicTagSession::BasicTagSession(std::weak_ptr<TagInfo> tagInfo, KITS::TagTechnology technology)
    : tagInfo_(tagInfo), tagTechnology_(technology), isConnected_(false)
{
}

OHOS::sptr<TAG::ITagSession> BasicTagSession::GetTagSessionProxy()
{
    bool isNfcOpen = false;
    NfcController::GetInstance().IsNfcOpen(isNfcOpen);
    if (!isNfcOpen) {
        ErrorLog("GetTagSessionProxy: nfc is not open");
        return nullptr;
    }
    return NfcController::GetInstance().GetTagSessionProxy();
}

int BasicTagSession::Connect()
{
    OHOS::sptr<TAG::ITagSession> tagSession = GetTagSessionProxy();
    if (tagSession == nullptr) {
        ErrorLog("Connect, ERR_TAG_STATE_UNBIND");
        return ErrorCode::ERR_TAG_STATE_UNBIND;
    }
    int tagRfDiscId = GetTagRfDiscId();
    int ret = tagSession->Connect(tagRfDiscId, static_cast<int>(tagTechnology_));
    if (ret == ErrorCode::ERR_NONE) {
        SetConnectedTagTech(tagTechnology_);
        isConnected_ = true;
    }
    return ret;
}

bool BasicTagSession::IsConnected()
{
    if (!isConnected_) {
        return false;
    }
    OHOS::sptr<TAG::ITagSession> tagSession = GetTagSessionProxy();
    if (tagSession == nullptr) {
        ErrorLog("IsConnected, ERR_TAG_STATE_UNBIND");
        return false;
    }
    isConnected_ = tagSession->IsTagFieldOn(GetTagRfDiscId());
    return isConnected_;
}

int BasicTagSession::Close()
{
    isConnected_ = false;
    OHOS::sptr<TAG::ITagSession> tagSession = GetTagSessionProxy();
    if (tagSession == nullptr || tagInfo_.expired()) {
        ErrorLog("Close, ERR_TAG_STATE_UNBIND");
        return ErrorCode::ERR_TAG_STATE_UNBIND;
    }

    // do reconnect to reset the tag's state.
    tagInfo_.lock()->SetConnectedTagTech(KITS::TagTechnology::NFC_INVALID_TECH);

    int statusCode = tagSession->Reconnect(GetTagRfDiscId());
    if (statusCode == ErrorCode::ERR_NONE) {
        SetConnectedTagTech(tagTechnology_);
    }
    return statusCode;
}

int BasicTagSession::SetTimeout(int timeout)
{
    OHOS::sptr<TAG::ITagSession> tagSession = GetTagSessionProxy();
    if (tagSession == nullptr) {
        ErrorLog("SetTimeout, ERR_TAG_STATE_UNBIND");
        return ErrorCode::ERR_TAG_STATE_UNBIND;
    }
    return tagSession->SetTimeout(GetTagRfDiscId(), timeout, static_cast<int>(tagTechnology_));
}

int BasicTagSession::GetTimeout(int &timeout)
{
    OHOS::sptr<TAG::ITagSession> tagSession = GetTagSessionProxy();
    if (tagSession == nullptr) {
        ErrorLog("GetTimeout, ERR_TAG_STATE_UNBIND");
        return ErrorCode::ERR_TAG_STATE_UNBIND;
    }
    return tagSession->GetTimeout(GetTagRfDiscId(), static_cast<int>(tagTechnology_), timeout);
}

void BasicTagSession::ResetTimeout()
{
    OHOS::sptr<TAG::ITagSession> tagSession = GetTagSessionProxy();
    if (tagSession == nullptr) {
        ErrorLog("ResetTimeout, ERR_TAG_STATE_UNBIND");
        return;
    }
    tagSession->ResetTimeout(GetTagRfDiscId());
}

std::string BasicTagSession::GetTagUid()
{
    if (tagInfo_.expired()) {
        return "";
    }
    return tagInfo_.lock()->GetTagUid();
}

int BasicTagSession::SendCommand(std::string& hexCmdData,
    bool raw, std::string &hexRespData)
{
    OHOS::sptr<TAG::ITagSession> tagSession = GetTagSessionProxy();
    if (tagSession == nullptr) {
        ErrorLog("BasicTagSession::SendCommand tagSession invalid");
        return ErrorCode::ERR_TAG_STATE_UNBIND;
    }
    return tagSession->SendRawFrame(GetTagRfDiscId(), hexCmdData, raw, hexRespData);
}

int BasicTagSession::GetMaxSendCommandLength(int &maxSize)
{
    if (tagInfo_.expired() || (tagTechnology_ == KITS::TagTechnology::NFC_INVALID_TECH)) {
        ErrorLog("GetMaxSendCommandLength ERR_TAG_PARAMETERS");
        return ErrorCode::ERR_TAG_PARAMETERS;
    }
    OHOS::sptr<TAG::ITagSession> tagSession = GetTagSessionProxy();
    if (tagSession == nullptr) {
        ErrorLog("GetMaxSendCommandLength ERR_TAG_STATE_UNBIND");
        return ErrorCode::ERR_TAG_STATE_UNBIND;
    }
    return tagSession->GetMaxTransceiveLength(static_cast<int>(tagTechnology_), maxSize);
}

int BasicTagSession::GetTagRfDiscId() const
{
    if (tagInfo_.expired()) {
        ErrorLog("[BasicTagSession::GetTagRfDiscId] tag is null.");
        return ErrorCode::ERR_TAG_PARAMETERS;
    }
    return tagInfo_.lock()->GetTagRfDiscId();
}

void BasicTagSession::SetConnectedTagTech(KITS::TagTechnology tech) const
{
    if (tagInfo_.expired()) {
        ErrorLog("[BasicTagSession::SetConnectedTagTech] tag is null.");
        return;
    }
    tagInfo_.lock()->SetConnectedTagTech(tech);
}

KITS::TagTechnology BasicTagSession::GetConnectedTagTech() const
{
    if (tagInfo_.expired()) {
        ErrorLog("[BasicTagSession::GetConnectedTagTech] tag is null.");
        return KITS::TagTechnology::NFC_INVALID_TECH;
    }

    return tagInfo_.lock()->GetConnectedTagTech();
}

std::weak_ptr<TagInfo> BasicTagSession::GetTagInfo() const
{
    return tagInfo_;
}
}  // namespace KITS
}  // namespace NFC
}  // namespace OHOS
