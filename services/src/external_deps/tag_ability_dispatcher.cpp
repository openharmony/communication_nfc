﻿/*
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
#include "tag_ability_dispatcher.h"
#include "ability_manager_client.h"
#include "app_data_parser.h"
#include "external_deps_proxy.h"
#include "loghelper.h"
#include "nfc_sdk_common.h"
#include "vibrator_agent.h"

namespace OHOS {
namespace NFC {
namespace TAG {
using OHOS::NFC::KITS::TagTechnology;
using OHOS::AppExecFwk::ElementName;

const std::string PARAM_ABILITY_APPINFOS = "ohos.ability.params.appInfos";

TagAbilityDispatcher::TagAbilityDispatcher()
{
}

TagAbilityDispatcher::~TagAbilityDispatcher()
{
}

void TagAbilityDispatcher::SetWantExtraParam(const std::shared_ptr<KITS::TagInfo>& tagInfo, AAFwk::Want& want)
{
    // put extra data for all included technology, extra data used by 3rd party applications.
    if (tagInfo == nullptr) {
        ErrorLog("TagAbilityDispatcher::SetWantExtraParam tagInfo is null");
        return;
    }
    want.SetParam("uid", tagInfo->GetTagUid());
    want.SetParam("technology", tagInfo->GetTagTechList());
    want.SetParam("tagRfDiscId", tagInfo->GetTagRfDiscId());

    std::vector<int> techList = tagInfo->GetTagTechList();
    for (size_t i = 0; i < techList.size(); i++) {
        AppExecFwk::PacMap extra = tagInfo->GetTechExtrasByIndex(i);
        if (techList[i] == static_cast<int>(TagTechnology::NFC_A_TECH)) {
            want.SetParam(KITS::TagInfo::SAK, extra.GetIntValue(KITS::TagInfo::SAK, 0));
            want.SetParam(KITS::TagInfo::ATQA, extra.GetStringValue(KITS::TagInfo::ATQA, ""));
        } else if (techList[i] == static_cast<int>(TagTechnology::NFC_B_TECH)) {
            want.SetParam(KITS::TagInfo::APP_DATA, extra.GetStringValue(KITS::TagInfo::APP_DATA, ""));
            want.SetParam(KITS::TagInfo::PROTOCOL_INFO, extra.GetStringValue(KITS::TagInfo::PROTOCOL_INFO, ""));
        } else if (techList[i] == static_cast<int>(TagTechnology::NFC_F_TECH)) {
            want.SetParam(KITS::TagInfo::NFCF_SC, extra.GetStringValue(KITS::TagInfo::NFCF_SC, ""));
            want.SetParam(KITS::TagInfo::NFCF_PMM, extra.GetStringValue(KITS::TagInfo::NFCF_PMM, ""));
        } else if (techList[i] == static_cast<int>(TagTechnology::NFC_V_TECH)) {
            want.SetParam(KITS::TagInfo::RESPONSE_FLAGS, extra.GetIntValue(KITS::TagInfo::RESPONSE_FLAGS, 0));
            want.SetParam(KITS::TagInfo::DSF_ID, extra.GetIntValue(KITS::TagInfo::DSF_ID, 0));
        } else if (techList[i] == static_cast<int>(TagTechnology::NFC_ISODEP_TECH)) {
            want.SetParam(KITS::TagInfo::HISTORICAL_BYTES, extra.GetStringValue(KITS::TagInfo::HISTORICAL_BYTES, ""));
            want.SetParam(KITS::TagInfo::HILAYER_RESPONSE, extra.GetStringValue(KITS::TagInfo::HILAYER_RESPONSE, ""));
        } else if (techList[i] == static_cast<int>(TagTechnology::NFC_MIFARE_ULTRALIGHT_TECH)) {
            want.SetParam(KITS::TagInfo::MIFARE_ULTRALIGHT_C_TYPE,
                extra.GetBooleanValue(KITS::TagInfo::MIFARE_ULTRALIGHT_C_TYPE, false));
        } else if (techList[i] == static_cast<int>(TagTechnology::NFC_NDEF_TECH)) {
            // set ndef message/type/max size/read mode for ndef tag
            want.SetParam(KITS::TagInfo::NDEF_MSG, extra.GetStringValue(KITS::TagInfo::NDEF_MSG, ""));
            want.SetParam(KITS::TagInfo::NDEF_FORUM_TYPE, extra.GetIntValue(KITS::TagInfo::NDEF_FORUM_TYPE, 0));
            want.SetParam(KITS::TagInfo::NDEF_TAG_LENGTH, extra.GetIntValue(KITS::TagInfo::NDEF_TAG_LENGTH, 0));
            want.SetParam(KITS::TagInfo::NDEF_TAG_MODE, extra.GetIntValue(KITS::TagInfo::NDEF_TAG_MODE, 0));
        }
    }
}

void TagAbilityDispatcher::StartVibratorOnce(bool isNtfPublished)
{
    if (isNtfPublished) {
        InfoLog("don't vibrate.");
        return;
    }
    InfoLog("Start vibrator once.");
    OHOS::Sensors::StartVibratorOnce(DEFAULT_MOTOR_VIBRATOR_ONCE);
}

void TagAbilityDispatcher::DispatchTagAbility(const std::shared_ptr<KITS::TagInfo>& tagInfo,
                                              OHOS::sptr<IRemoteObject> tagServiceIface)
{
    if (tagInfo == nullptr) {
        ErrorLog("DispatchTagAbility tagInfo is null");
        return;
    }
    if (tagServiceIface == nullptr) {
        WarnLog("DispatchTagAbility tagServiceIface is null");
    }

    std::vector<int> techList = tagInfo->GetTagTechList();
    std::vector<ElementName> elements = AppDataParser::GetInstance().GetDispatchTagAppsByTech(techList);
#ifdef VENDOR_APPLICATIONS_ENABLED
    std::vector<ElementName> vendorElements = AppDataParser::GetInstance().GetVendorDispatchTagAppsByTech(techList);
    if (elements.size() == 0 && vendorElements.size() == 0) {
        ExternalDepsProxy::GetInstance().PublishNfcNotification(NFC_NO_HAP_SUPPORTED_NOTIFICATION_ID, "", 0);
        return;
    }

    AAFwk::Want want;
    std::vector<std::string> vendorElementNameList;
    for (auto vendorElement : vendorElements) {
        std::string elementName = vendorElement.GetBundleName() + vendorElement.GetAbilityName();
        vendorElementNameList.push_back(elementName);
    }

    want.SetParam("remoteTagService", tagServiceIface);
    SetWantExtraParam(tagInfo, want);
    want.SetParam(PARAM_ABILITY_APPINFOS, vendorElementNameList);
    DispatchAbilityMultiApp(tagInfo, want);
#else
    if (elements.size() == 0) {
        return;
    }
    AAFwk::Want want;
    want.SetParam("remoteTagService", tagServiceIface);
    SetWantExtraParam(tagInfo, want);
    if (elements.size() == TAG_APP_MATCHED_SIZE_SINGLE) {
        want.SetElement(elements[0]);
        DispatchAbilitySingleApp(want);
    } else {
        DispatchAbilityMultiApp(tagInfo, want);
    }
#endif
}

void TagAbilityDispatcher::DispatchAbilityMultiApp(const std::shared_ptr<KITS::TagInfo>& tagInfo, AAFwk::Want& want)
{
    InfoLog("DispatchAbilityMultiApp for app");
    if (tagInfo == nullptr) {
        ErrorLog("DispatchTagAbility tagInfo is null");
        return;
    }

    // pull multi app page by skill.uris
    want.SetAction(KITS::ACTION_TAG_FOUND);
    std::vector<std::string> techArray;
    const std::string tagTechStr = "tag-tech/"; // exmaple: "tag-tech/NfcA"
    for (const auto& tagTech : tagInfo->GetTagTechList()) {
        if (tagTech < static_cast<int>(TagTechnology::NFC_A_TECH) ||
            tagTech > static_cast<int>(TagTechnology::NFC_MIFARE_ULTRALIGHT_TECH)) {
            WarnLog("DispatchAbilityMultiApp tagTech(%{public}d) out of range. ", tagTech);
            continue;
        }
        techArray.push_back(tagTechStr + KITS::TagInfo::GetStringTech(tagTech));
    }
    want.SetParam(AAFwk::Want::PARAM_ABILITY_URITYPES, techArray);

    if (AAFwk::AbilityManagerClient::GetInstance() == nullptr) {
        ErrorLog("DispatchAbilityMultiApp AbilityManagerClient is null");
        return;
    }

    AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    InfoLog("DispatchAbilityMultiApp call StartAbility end.");
    ExternalDepsProxy::GetInstance().WriteDispatchToAppHiSysEvent(want.GetElement().GetBundleName(),
        SubErrorCode::UNKNOWN_TAG_DISPATCH);
}

void TagAbilityDispatcher::DispatchAppGallery(OHOS::sptr<IRemoteObject> tagServiceIface,
                                              std::string appGalleryBundleName)
{
    InfoLog("DispatchAppGallery appGalleryBundleName = %{public}s", appGalleryBundleName.c_str());
    AAFwk::Want want;
    const std::string ABILITY_NAME = "MainAbility";
    want.SetParam("remoteTagService", tagServiceIface);
    want.SetElementName(appGalleryBundleName, ABILITY_NAME);
    DispatchAbilitySingleApp(want);
}

void TagAbilityDispatcher::DispatchAbilitySingleApp(AAFwk::Want& want)
{
    if (AAFwk::AbilityManagerClient::GetInstance() == nullptr) {
        ErrorLog("DispatchAbilitySingleApp AbilityManagerClient is null");
        return;
    }
    AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    InfoLog("DispatchAbilitySingleApp call StartAbility end.");
    ExternalDepsProxy::GetInstance().WriteDispatchToAppHiSysEvent(want.GetElement().GetBundleName(),
        SubErrorCode::UNKNOWN_TAG_DISPATCH);
}
}  // namespace TAG
}  // namespace NFC
}  // namespace OHOS
