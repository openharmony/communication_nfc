/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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
#include "tag_dispatcher.h"
#include <functional>
#include "app_data_parser.h"
#include "loghelper.h"
#include "ndef_message.h"
#include "nfc_hisysevent.h"
#include "nfc_sdk_common.h"
#include "run_on_demaind_manager.h"
#include "tag_ability_dispatcher.h"

namespace OHOS {
namespace NFC {
namespace TAG {
using OHOS::NFC::KITS::TagTechnology;
TagDispatcher::TagDispatcher(std::shared_ptr<NFC::NfcService> nfcService)
    : nfcService_(nfcService),
    lastNdefMsg_("")
{
    if (nfcService_) {
        nciTagProxy_ = nfcService_->GetNciTagProxy();
    }
}

TagDispatcher::~TagDispatcher()
{
}

void TagDispatcher::HandleTagFound(uint32_t tagDiscId)
{
    if (nfcService_ == nullptr || nciTagProxy_.expired() || nfcService_->GetNfcPollingManager().expired()) {
        ErrorLog("HandleTagFound, invalid state.");
        return;
    }

    int fieldOnCheckInterval_ = DEFAULT_FIELD_ON_CHECK_DURATION;
    if (nciTagProxy_.lock()->GetConnectedTech(tagDiscId) == static_cast<int>(TagTechnology::NFC_ISODEP_TECH)) {
        fieldOnCheckInterval_ = DEFAULT_ISO_DEP_FIELD_ON_CHECK_DURATION;
    }
    DebugLog("HandleTagFound fieldOnCheckInterval_ = %{public}d", fieldOnCheckInterval_);

    // skip ndef checking for foreground dispatch scenario
    if (nfcService_->GetNfcPollingManager().lock()->IsForegroundEnabled()) {
        nciTagProxy_.lock()->StartFieldOnChecking(tagDiscId, fieldOnCheckInterval_);
        nfcService_->GetNfcPollingManager().lock()->SendTagToForeground(GetTagInfoParcelableFromTag(tagDiscId));
        return;
    }
    std::string ndefMsg = nciTagProxy_.lock()->FindNdefTech(tagDiscId);
    std::shared_ptr<KITS::NdefMessage> ndefMessage = KITS::NdefMessage::GetNdefMessage(ndefMsg);
    if (ndefMessage == nullptr) {
        if (!nciTagProxy_.lock()->Reconnect(tagDiscId)) {
            nciTagProxy_.lock()->Disconnect(tagDiscId);
            ErrorLog("HandleTagFound bad connection, tag disconnected");
            return;
        }
    }
    lastNdefMsg_ = ndefMsg;
    nciTagProxy_.lock()->StartFieldOnChecking(tagDiscId, fieldOnCheckInterval_);
    if (nfcService_->GetNfcPollingManager().lock()->IsForegroundEnabled()) {
        nfcService_->GetNfcPollingManager().lock()->SendTagToForeground(GetTagInfoParcelableFromTag(tagDiscId));
        return;
    }
    DispatchTag(tagDiscId);
}


void TagDispatcher::HandleTagLost(uint32_t tagDiscId)
{
    InfoLog("HandleTagLost, tagDiscId: %{public}d", tagDiscId);
}

std::shared_ptr<KITS::TagInfo> TagDispatcher::GetTagInfoFromTag(uint32_t tagDiscId)
{
    std::vector<int> techList = nciTagProxy_.lock()->GetTechList(tagDiscId);
    std::string tagUid = nciTagProxy_.lock()->GetTagUid(tagDiscId);
    std::vector<AppExecFwk::PacMap> tagTechExtras = nciTagProxy_.lock()->GetTechExtrasData(tagDiscId);
    DebugLog("GetTagInfoFromTag: techListLen = %{public}zu, extrasLen = %{public}zu, tagUid = %{private}s,"
        " rfID = %{public}d", techList.size(), tagTechExtras.size(), tagUid.c_str(), tagDiscId);
    return std::make_shared<KITS::TagInfo>(techList, tagTechExtras, tagUid, tagDiscId,
        nfcService_->GetTagServiceIface());
}

KITS::TagInfoParcelable TagDispatcher::GetTagInfoParcelableFromTag(uint32_t tagDiscId)
{
    std::vector<int> techList = nciTagProxy_.lock()->GetTechList(tagDiscId);
    std::string tagUid = nciTagProxy_.lock()->GetTagUid(tagDiscId);
    std::vector<AppExecFwk::PacMap> tagTechExtras = nciTagProxy_.lock()->GetTechExtrasData(tagDiscId);
    DebugLog("GetTagInfoParcelableFromTag: techListLen = %{public}zu, extrasLen = %{public}zu, tagUid = %{private}s,"
        " rfID = %{public}d", techList.size(), tagTechExtras.size(), tagUid.c_str(), tagDiscId);
    KITS::TagInfoParcelable *tagInfo = new (std::nothrow) KITS::TagInfoParcelable(techList, tagTechExtras,
        tagUid, tagDiscId, nfcService_->GetTagServiceIface());
    return *(tagInfo);
}

void TagDispatcher::DispatchTag(uint32_t tagDiscId)
{
    std::shared_ptr<KITS::TagInfo> tagInfo = GetTagInfoFromTag(tagDiscId);
    if (tagInfo == nullptr) {
        ErrorLog("DispatchTag: taginfo is null");
        return;
    }

    // select the matched applications, try start ability
    std::vector<int> techList = nciTagProxy_.lock()->GetTechList(tagDiscId);
    // Record types of read tags.
    int tagFoundCnt = 0;
    int typeATagFoundCnt = 0;
    int typeBTagFoundCnt = 0;
    int typeFTagFoundCnt = 0;
    int typeVTagFoundCnt = 0;
    for (size_t i = 0; i < techList.size(); i++) {
        std::string discStrTech = KITS::TagInfo::GetStringTech(techList[i]);
        if (discStrTech.compare("NfcA") == 0) {
            tagFoundCnt++;
            typeATagFoundCnt++;
        } else if (discStrTech.compare("NfcB") == 0) {
            tagFoundCnt++;
            typeBTagFoundCnt++;
        } else if (discStrTech.compare("NfcF") == 0) {
            tagFoundCnt++;
            typeFTagFoundCnt++;
        } else if (discStrTech.compare("NfcV") == 0) {
            tagFoundCnt++;
            typeVTagFoundCnt++;
        } else {
            tagFoundCnt++;
        }
    }
    RunOnDemaindManager::GetInstance().WriteTagFoundHiSysEvent(tagFoundCnt, typeATagFoundCnt,
        typeBTagFoundCnt, typeFTagFoundCnt, typeVTagFoundCnt);

    // start application ability for tag found.
    RunOnDemaindManager::GetInstance().DispatchTagAbility(tagInfo, nfcService_->GetTagServiceIface());
}

void TagDispatcher::HandleTagDebounce()
{
    DebugLog("HandleTagDebounce, unimplimentation...");
}
}  // namespace TAG
}  // namespace NFC
}  // namespace OHOS
