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
#include "app_data_parser.h"

#include "accesstoken_kit.h"
#include "common_event_manager.h"
#include "iservice_registry.h"
#include "loghelper.h"
#include "nfc_sdk_common.h"
#include "system_ability_definition.h"
#include "taginfo.h"
#include "nfc_permission_checker.h"

namespace OHOS {
namespace NFC {
const int USER_ID = 100;
static AppDataParser g_appDataParser;
/** Tag type of tag app metadata name */
static const std::string KEY_TAG_TECH = "tag-tech";
std::mutex g_mutex = {};
sptr<BundleMgrDeathRecipient> bundleMgrDeathRecipient_(new BundleMgrDeathRecipient());

void BundleMgrDeathRecipient::OnRemoteDied([[maybe_unused]] const wptr<IRemoteObject> &remote)
{
    InfoLog("bundleMgrService dead");
};

AppDataParser::AppDataParser()
{
    g_tagAppAndTechMap.clear();
    g_hceAppAndAidMap.clear();
}

AppDataParser::~AppDataParser()
{
}

AppDataParser& AppDataParser::GetInstance()
{
    return g_appDataParser;
}

sptr<AppExecFwk::IBundleMgr> AppDataParser::GetBundleMgrProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ErrorLog("GetBundleMgrProxy, systemAbilityManager is null");
        return nullptr;
    }
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        ErrorLog("GetBundleMgrProxy, remoteObject is null");
        return nullptr;
    }
    sptr<AppExecFwk::IBundleMgr> bundleMgrProxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    bundleMgrProxy->AsObject()->AddDeathRecipient(bundleMgrDeathRecipient_);
    return bundleMgrProxy;
}

bool AppDataParser::HandleAppAddOrChangedEvent(std::shared_ptr<EventFwk::CommonEventData> data)
{
    if (data == nullptr) {
        ErrorLog("HandleAppAddOrChangedEvent, invalid data.");
        return false;
    }
    ElementName element = data->GetWant().GetElement();
    std::string bundleName = element.GetBundleName();
    if (bundleName.empty()) {
        ErrorLog("HandleAppAddOrChangedEvent, invaid bundleName.");
        return false;
    }
    OHOS::AAFwk::Want want = data->GetWant();
    int32_t appIndex = want.GetIntParam(AppExecFwk::Constants::APP_INDEX, AppExecFwk::Constants::DEFAULT_APP_INDEX);
    DebugLog("HandleAppAddOrChangedEvent bundlename: %{public}s, appIndex: %{public}d", bundleName.c_str(), appIndex);
    bool tag = UpdateAppListInfo(element, KITS::ACTION_TAG_FOUND);
    bool host = UpdateAppListInfo(element, KITS::ACTION_HOST_APDU_SERVICE, appIndex);
    bool offHost = UpdateAppListInfo(element, KITS::ACTION_OFF_HOST_APDU_SERVICE);
    return tag || host || offHost;
}

bool AppDataParser::HandleAppRemovedEvent(std::shared_ptr<EventFwk::CommonEventData> data)
{
    if (data == nullptr) {
        ErrorLog("HandleAppRemovedEvent, invalid data.");
        return false;
    }
    ElementName element = data->GetWant().GetElement();
    std::string bundleName = element.GetBundleName();
    if (bundleName.empty()) {
        ErrorLog("HandleAppRemovedEvent, invalid bundleName.");
        return false;
    }
    OHOS::AAFwk::Want want = data->GetWant();
    int32_t appIndex = want.GetIntParam(AppExecFwk::Constants::APP_INDEX, AppExecFwk::Constants::DEFAULT_APP_INDEX);
    DebugLog("HandleAppRemovedEvent, bundleName %{public}s appIndex: %{public}d"
        "tag size %{public}zu, hce size %{public}zu",
        bundleName.c_str(),
        appIndex,
        g_tagAppAndTechMap.size(),
        g_hceAppAndAidMap.size());
    bool tag = RemoveTagAppInfo(element);
    bool hce = RemoveHceAppInfo(element, appIndex);
    bool offHost = RemoveOffHostAppInfo(element);
    return tag || hce || offHost;
}

bool AppDataParser::VerifyHapPermission(const std::string bundleName, const std::string action)
{
    std::string permissionNfc;
    OHOS::Security::AccessToken::AccessTokenID tokenID;
    std::map<std::string, std::string> permissionMap = {
        {KITS::ACTION_TAG_FOUND, TAG_PERM},
        {KITS::ACTION_HOST_APDU_SERVICE, CARD_EMU_PERM},
        {KITS::ACTION_OFF_HOST_APDU_SERVICE, CARD_EMU_PERM}
    };
    std::map<std::string, std::string>::iterator it = permissionMap.find(action.c_str());
    if (it != permissionMap.end()) {
        permissionNfc = it->second;
    } else {
        ErrorLog("VerifyHapPermission, action no in map!");
        return false;
    }
    tokenID= OHOS::Security::AccessToken::AccessTokenKit::GetHapTokenID(USER_ID, bundleName, 0);
    int result = OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenID, permissionNfc);
    if (result != OHOS::Security::AccessToken::PERMISSION_GRANTED) {
        ErrorLog("bundleName %{public}s no permission %{public}s", bundleName.c_str(), permissionNfc.c_str());
        return false;
    }
    return true;
}

void AppDataParser::QueryAbilityInfos(const std::string action, std::vector<AbilityInfo> &abilityInfos,
    std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    sptr<AppExecFwk::IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    if (bundleMgrProxy == nullptr) {
        ErrorLog("QueryAbilityInfos, bundleMgrProxy is nullptr.");
        return;
    }
    AAFwk::Want want;
    want.SetAction(action);
    if (KITS::ACTION_TAG_FOUND == action) {
        // only tag action have uris
        want.SetType("*/*");
    }

    bool withDefault = false;
    bool findDefaultApp = false;
    auto abilityInfoFlag = AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_DEFAULT
        | AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_SKILL_URI
        | AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_METADATA;
    if (!bundleMgrProxy->ImplicitQueryInfos(want, abilityInfoFlag, USER_ID, withDefault,
        abilityInfos, extensionInfos, findDefaultApp)) {
        WarnLog("QueryAbilityInfos, query none for action %{public}s", action.c_str());
        return;
    }
}

bool AppDataParser::UpdateAppListInfo(ElementName &element, const std::string action, int32_t appIndex)
{
    if (action.compare(KITS::ACTION_TAG_FOUND) != 0 && action.compare(KITS::ACTION_HOST_APDU_SERVICE) != 0 &&
        action != KITS::ACTION_OFF_HOST_APDU_SERVICE) {
        DebugLog("UpdateAppListInfo, ignore action = %{public}s", action.c_str());
        return false;
    }
    std::string bundleName = element.GetBundleName();
    if (!VerifyHapPermission(bundleName, action)) {
        DebugLog("Hap have no permission for action = %{public}s", action.c_str());
        return false;
    }

    // query the applications infos that're matched with the acitons.
    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionAbilityInfos;
    QueryAbilityInfos(action, abilityInfos, extensionAbilityInfos);
    for (auto& abilityInfo : abilityInfos) {
        if (bundleName.empty() || bundleName.compare(abilityInfo.bundleName) != 0) {
            continue;
        }
        ElementName hapElement(abilityInfo.deviceId, abilityInfo.bundleName, abilityInfo.name,
                abilityInfo.moduleName);
        if (action.compare(KITS::ACTION_TAG_FOUND) == 0) {
            UpdateTagAppList(abilityInfo, hapElement);
        }
        if (action.compare(KITS::ACTION_HOST_APDU_SERVICE) == 0) {
            UpdateHceAppList(abilityInfo, hapElement, appIndex);
        }
        if (action.compare(KITS::ACTION_OFF_HOST_APDU_SERVICE) == 0) {
            UpdateOffHostAppList(abilityInfo, hapElement);
        }
    }
    return true;
}

bool AppDataParser::InitAppListByAction(const std::string action)
{
    // query the applications infos that're matched with the acitons.
    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionAbilityInfos;
    QueryAbilityInfos(action, abilityInfos, extensionAbilityInfos);
    if (KITS::ACTION_TAG_FOUND.compare(action) == 0) {
        for (auto& tagAbilityInfo : abilityInfos) {
            ElementName element(tagAbilityInfo.deviceId, tagAbilityInfo.bundleName, tagAbilityInfo.name,
                tagAbilityInfo.moduleName);
            UpdateTagAppList(tagAbilityInfo, element);
        }
    } else if (KITS::ACTION_HOST_APDU_SERVICE.compare(action) == 0) {
        for (auto& hceAbilityInfo : abilityInfos) {
            ElementName element(hceAbilityInfo.deviceId, hceAbilityInfo.bundleName, hceAbilityInfo.name,
                hceAbilityInfo.moduleName);
            UpdateHceAppList(hceAbilityInfo, element);
        }
    } else if (KITS::ACTION_OFF_HOST_APDU_SERVICE.compare(action) == 0) {
        for (auto& offHostAbilityInfo : abilityInfos) {
            ElementName element(offHostAbilityInfo.deviceId, offHostAbilityInfo.bundleName, offHostAbilityInfo.name,
                offHostAbilityInfo.moduleName);
            UpdateOffHostAppList(offHostAbilityInfo, element);
        }
    } else {
        WarnLog("InitAppListByAction,unknown action = %{public}s", action.c_str());
    }
    return true;
}

bool AppDataParser::IsMatchedByBundleName(ElementName &src, ElementName &target)
{
    if (src.GetBundleName().compare(target.GetBundleName()) == 0) {
        return true;
    }
    return false;
}

ElementName AppDataParser::GetMatchedTagKeyElement(ElementName &element)
{
    ElementName emptyElement;
    std::vector<TagAppTechInfo>::iterator iter;
    for (iter = g_tagAppAndTechMap.begin(); iter != g_tagAppAndTechMap.end(); ++iter) {
        if (IsMatchedByBundleName(element, (*iter).element)) {
            return (*iter).element;
        }
    }
    return emptyElement;
}

ElementName AppDataParser::GetMatchedHceKeyElement(ElementName &element, int32_t appIndex)
{
    ElementName emptyElement;
    std::vector<HceAppAidInfo>::iterator iter;
    for (iter = g_hceAppAndAidMap.begin(); iter != g_hceAppAndAidMap.end(); ++iter) {
        if (IsMatchedByBundleName(element, (*iter).element) && (*iter).appIndex == appIndex) {
            return (*iter).element;
        }
    }
    return emptyElement;
}

void AppDataParser::UpdateTagAppList(AbilityInfo &abilityInfo, ElementName &element)
{
    if (!GetMatchedTagKeyElement(element).GetBundleName().empty()) {
        WarnLog("UpdateTagAppList, rm duplicated app %{public}s", element.GetBundleName().c_str());
        RemoveTagAppInfo(element);
    }
    std::vector<std::string> valueList;
    for (auto& data : abilityInfo.metadata) {
        if (KEY_TAG_TECH.compare(data.name) == 0) {
            valueList.emplace_back(data.value);
            DebugLog("UpdateTagAppList from metadata, push tech %{public}s", data.value.c_str());
        }
    }
    for (auto& data : abilityInfo.metaData.customizeData) {
        if (KEY_TAG_TECH.compare(data.name) == 0) {
            valueList.emplace_back(data.value);
            DebugLog("UpdateTagAppList from customizeData, push tech %{public}s", data.value.c_str());
        }
    }
    for (auto& uri : abilityInfo.skillUri) {
        if (uri.type.empty()) {
            continue;
        }
        // format example: "type": "tag-tech/NfcA"
        auto pos = uri.type.find("/");
        if (pos == std::string::npos) {
            ErrorLog("UpdateTagAppList from skillUri, separator not found %{public}s", uri.type.c_str());
            continue;
        }
        std::string tech = uri.type.substr(0, pos);
        if (KEY_TAG_TECH.compare(tech) != 0) {
            ErrorLog("UpdateTagAppList KEY_TAG_TECH for %{public}s", tech.c_str());
            continue;
        }
        std::string nfcType = uri.type.substr(pos + 1, uri.type.size());
        if (std::find(valueList.begin(), valueList.end(), nfcType) == valueList.end()) {
            valueList.emplace_back(nfcType);
            DebugLog("UpdateTagAppList from skillUri, push tech %{public}s", nfcType.c_str());
        }
    }

    if (valueList.empty()) {
        DebugLog("UpdateTagAppList, ignore for app %{public}s %{public}s", element.GetBundleName().c_str(),
            element.GetAbilityName().c_str());
        return;
    }

    TagAppTechInfo tagAppTechInfo;
    tagAppTechInfo.element = element;
    tagAppTechInfo.tech = valueList;
    g_tagAppAndTechMap.push_back(tagAppTechInfo);
    DebugLog("UpdateTagAppList, push for app %{public}s %{public}s", element.GetBundleName().c_str(),
        element.GetAbilityName().c_str());
}

void AppDataParser::UpdateHceAppList(AbilityInfo &abilityInfo, ElementName &element, int32_t appIndex)
{
    if (!GetMatchedHceKeyElement(element, appIndex).GetBundleName().empty()) {
        WarnLog("UpdateHceAppList, rm duplicated app %{public}s", element.GetBundleName().c_str());
        RemoveHceAppInfo(element, appIndex);
    }
    std::vector<AidInfo> customDataAidList;
    AidInfo customDataAid;
    for (auto& data : abilityInfo.metadata) {
        if ((KITS::KEY_PAYMENT_AID.compare(data.name) == 0) || (KITS::KEY_OHTER_AID.compare(data.name) == 0)) {
            customDataAid.name = data.name;
            customDataAid.value = data.value;
            customDataAidList.emplace_back(customDataAid);
            InfoLog("UpdateHceAppList from metadata, push aid %{public}s", data.value.c_str());
        }
    }
    for (auto& data : abilityInfo.metaData.customizeData) {
        if ((KITS::KEY_PAYMENT_AID.compare(data.name) == 0) || (KITS::KEY_OHTER_AID.compare(data.name) == 0)) {
            customDataAid.name = data.name;
            customDataAid.value = data.value;
            customDataAidList.emplace_back(customDataAid);
            InfoLog("UpdateHceAppList from customizeData, push aid %{public}s", data.value.c_str());
        }
    }
    // hce App without static aid config should also be added into g_hceAppAndAidMap for invoking HceService.on
    if (customDataAidList.empty()) {
        WarnLog("UpdateHceAppList, app %{public}s %{public}s has no static aid config", element.GetBundleName().c_str(),
            element.GetAbilityName().c_str());
    }
    HceAppAidInfo hceAppAidInfo;
    hceAppAidInfo.element = element;
    hceAppAidInfo.iconId = abilityInfo.iconId;
    hceAppAidInfo.labelId = abilityInfo.labelId;
    hceAppAidInfo.appIndex = appIndex;
    hceAppAidInfo.customDataAid = customDataAidList;
    g_hceAppAndAidMap.push_back(hceAppAidInfo);
    DebugLog("UpdateHceAppList, push for app %{public}s %{public}s", element.GetBundleName().c_str(),
        element.GetAbilityName().c_str());
}

void AppDataParser::UpdateOffHostAppList(AbilityInfo &abilityInfo, ElementName &element)
{
    if (HaveMatchedOffHostKeyElement(element)) {
        WarnLog("UpdateOffHostAppList, rm duplicated app %{public}s", element.GetBundleName().c_str());
        RemoveOffHostAppInfo(element);
    }
    HceAppAidInfo offHostAppAidInfo;
    offHostAppAidInfo.element = element;
    offHostAppAidInfo.iconId = abilityInfo.iconId;
    offHostAppAidInfo.labelId = abilityInfo.labelId;
    g_offHostAppAndAidMap.push_back(offHostAppAidInfo);
    DebugLog("UpdateOffHostAppList, push for app %{public}s %{public}s", element.GetBundleName().c_str(),
        element.GetAbilityName().c_str());
}

bool AppDataParser::HaveMatchedOffHostKeyElement(ElementName &element)
{
    std::vector<HceAppAidInfo>::iterator iter;
    for (iter = g_offHostAppAndAidMap.begin(); iter != g_offHostAppAndAidMap.end(); ++iter) {
        if (IsMatchedByBundleName(element, (*iter).element)) {
            return true;
        }
    }
    return false;
}

bool AppDataParser::RemoveTagAppInfo(ElementName &element)
{
    ElementName keyElement = GetMatchedTagKeyElement(element);
    if (keyElement.GetBundleName().empty()) {
        WarnLog("RemoveTagAppInfo, keyElement is none, ignore it.");
        return false;
    }
    DebugLog("RemoveTagAppInfo, request app %{public}s", keyElement.GetBundleName().c_str());
    std::vector<TagAppTechInfo>::iterator iter;
    for (iter = g_tagAppAndTechMap.begin(); iter != g_tagAppAndTechMap.end(); ++iter) {
        // compare only bundle name to remote the app.
        if (IsMatchedByBundleName(element, (*iter).element)) {
            DebugLog("RemoveTagAppInfo, erase app %{public}s", keyElement.GetBundleName().c_str());
            g_tagAppAndTechMap.erase(iter);
            return true;
        }
    }
    return false;
}

bool AppDataParser::RemoveHceAppInfo(ElementName &element, int32_t appIndex)
{
    ElementName keyElement = GetMatchedHceKeyElement(element, appIndex);
    if (keyElement.GetBundleName().empty()) {
        WarnLog("RemoveHceAppInfo, keyElement is none, ignore it.");
        return false;
    }
    DebugLog("RemoveHceAppInfo, app %{public}s", keyElement.GetBundleName().c_str());
    std::vector<HceAppAidInfo>::iterator iter;
    for (iter = g_hceAppAndAidMap.begin(); iter != g_hceAppAndAidMap.end(); ++iter) {
        // compare only bundle name to remote the app.
        if (IsMatchedByBundleName(element, (*iter).element) && (*iter).appIndex == appIndex) {
            DebugLog("RemoveHceAppInfo, erase app %{public}s, appIndex = %{public}d",
                keyElement.GetBundleName().c_str(), appIndex);
            g_hceAppAndAidMap.erase(iter);
            return true;
        }
    }
    return false;
}

bool AppDataParser::RemoveOffHostAppInfo(ElementName &element)
{
    if (!HaveMatchedOffHostKeyElement(element)) {
        WarnLog("RemoveOffHostAppInfo, keyElement is none, ignore it.");
        return false;
    }

    DebugLog("RemoveOffHostAppInfo, app %{public}s", element.GetBundleName().c_str());
    std::vector<HceAppAidInfo>::iterator iter;
    for (iter = g_offHostAppAndAidMap.begin(); iter != g_offHostAppAndAidMap.end(); ++iter) {
        // compare only bundle name to remote the app.
        if (IsMatchedByBundleName(element, (*iter).element)) {
            DebugLog("RemoveOffHostAppInfo, erase app %{public}s", element.GetBundleName().c_str());
            g_offHostAppAndAidMap.erase(iter);
            return true;
        }
    }
    return false;
}

void AppDataParser::InitAppList()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (appListInitDone_) {
        WarnLog("InitAppList: already done");
        return;
    }
    sptr<AppExecFwk::IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        ErrorLog("InitAppList, bundleMgrProxy is nullptr.");
        appListInitDone_ = false;
        return;
    }
    InfoLog("InitAppListByAction start");
    InitAppListByAction(KITS::ACTION_TAG_FOUND);
    InitAppListByAction(KITS::ACTION_HOST_APDU_SERVICE);
    InitAppListByAction(KITS::ACTION_OFF_HOST_APDU_SERVICE);
    InfoLog("InitAppList, tag size %{public}zu, hce size %{public}zu, off host app  %{public}zu",
            g_tagAppAndTechMap.size(), g_hceAppAndAidMap.size(), g_offHostAppAndAidMap.size());
    appListInitDone_ = true;
}

std::vector<ElementName> AppDataParser::GetDispatchTagAppsByTech(std::vector<int> discTechList)
{
    std::vector<ElementName> elements;
    for (size_t i = 0; i < discTechList.size(); i++) {
        std::string discStrTech = KITS::TagInfo::GetStringTech(discTechList[i]);
        DebugLog("GetDispatchTagAppsByTech, tag size = %{public}zu", g_tagAppAndTechMap.size());
        if (discStrTech.empty()) {
            continue;
        }

        // parse for all installed app that can handle this technology.
        std::vector<TagAppTechInfo>::iterator iter;
        for (iter = g_tagAppAndTechMap.begin(); iter != g_tagAppAndTechMap.end(); ++iter) {
            bool appExisted = false;
            for (auto item : elements) {
                if (IsMatchedByBundleName(item, (*iter).element)) {
                    appExisted = true;
                    break;
                }
            }
            if (appExisted) {
                continue;
            }

            std::vector<std::string> vectorTech = (*iter).tech;
            for (size_t i = 0; i < vectorTech.size(); i++) {
                DebugLog("GetDispatchTagAppsByTech, cmp tech %{public}s vs %{public}s",
                    discStrTech.c_str(), vectorTech[i].c_str());
                if (discStrTech.compare(vectorTech[i]) == 0) {
                    elements.push_back((*iter).element);
                    break;
                }
            }
        }
    }
    return elements;
}

#ifdef VENDOR_APPLICATIONS_ENABLED
std::vector<ElementName> AppDataParser::GetVendorDispatchTagAppsByTech(std::vector<int>& discTechList)
{
    std::vector<ElementName> elements {};
    std::vector<AAFwk::Want> hceAppList {};
    std::lock_guard<std::mutex> lock(g_mutex);
    if (queryApplicationByVendor_ == nullptr) {
        ErrorLog("AppDataParser::GetVendorDispatchTagAppsByTech queryApplicationByVendor_ is nullptr.");
        return std::vector<ElementName>();
    }
    queryApplicationByVendor_->OnQueryAppInfo(KEY_TAG_APP, discTechList, hceAppList, elements);
    return elements;
}

void AppDataParser::RegQueryApplicationCb(sptr<IQueryAppInfoCallback> callback)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    queryApplicationByVendor_ = callback;
}

void AppDataParser::RegCardEmulationNotifyCb(sptr<IOnCardEmulationNotifyCb> callback)
{
    onCardEmulationNotify_ = callback;
}

sptr<IOnCardEmulationNotifyCb> AppDataParser::GetNotifyCardEmulationCallback() const
{
    return onCardEmulationNotify_;
}
#endif

void AppDataParser::GetHceAppsByAid(const std::string& aid, std::vector<AppDataParser::HceAppAidInfo>& hceApps)
{
    for (const HceAppAidInfo& appAidInfo : g_hceAppAndAidMap) {
        for (const AidInfo& aidInfo : appAidInfo.customDataAid) {
            if (aid == aidInfo.value) {
                hceApps.push_back(appAidInfo);
                break;
            }
        }
    }
}

#ifdef VENDOR_APPLICATIONS_ENABLED
void AppDataParser::GetHceAppsFromVendor(std::vector<HceAppAidInfo> &hceApps)
{
    std::vector<int> techList {};
    std::vector<AAFwk::Want> vendorHceAppAndAidList {};
    std::vector<AppExecFwk::ElementName> elementNameList {};
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (queryApplicationByVendor_ == nullptr) {
            WarnLog("AppDataParser::GetHceApps queryApplicationByVendor_ is nullptr.");
            return;
        }
        queryApplicationByVendor_->OnQueryAppInfo(KEY_HCE_APP, techList, vendorHceAppAndAidList, elementNameList);
    }
    if (vendorHceAppAndAidList.size() != 0) {
        for (auto appAidInfoWant : vendorHceAppAndAidList) {
            std::shared_ptr<HceAppAidInfo> appAidInfo = std::make_shared<HceAppAidInfo>();
            appAidInfo->element = appAidInfoWant.GetElement();
            const std::string KEY_OTHER_AID = "other-aid";
            const std::string KEY_PAYMENT_AID = "payment-aid";
            std::vector<std::string> otherAidList = appAidInfoWant.GetStringArrayParam(KEY_OTHER_AID);
            std::vector<std::string> paymentAidList = appAidInfoWant.GetStringArrayParam(KEY_PAYMENT_AID);
            for (std::string otherAid : otherAidList) {
                std::shared_ptr<AidInfo> aidInfo = std::make_shared<AidInfo>();
                aidInfo->name = KEY_OTHER_AID;
                aidInfo->value = otherAid;
                appAidInfo->customDataAid.push_back(*aidInfo);
            }
            for (std::string paymentAid : paymentAidList) {
                std::shared_ptr<AidInfo> aidInfo = std::make_shared<AidInfo>();
                aidInfo->name = KEY_PAYMENT_AID;
                aidInfo->value = paymentAid;
                appAidInfo->customDataAid.push_back(*aidInfo);
            }
            hceApps.push_back(*appAidInfo);
        }
    }
}

void AppDataParser::GetPaymentAbilityInfosFromVendor(std::vector<AbilityInfo> &paymentAbilityInfos)
{
    std::vector<HceAppAidInfo> hceApps;
    std::set<std::string> bundleNames;
    GetHceAppsFromVendor(hceApps);
    DebugLog("The hceApps len %{public}lu", hceApps.size());
    sptr<AppExecFwk::IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    if (bundleMgrProxy == nullptr) {
        ErrorLog("bundleMgrProxy is nullptr!");
        return;
    }
    for (auto& appAidInfo : hceApps) {
        DebugLog("The bundlename : %{public}s", appAidInfo.element.GetBundleName().c_str());
        if (appAidInfo.element.GetBundleName().empty() || !IsPaymentApp(appAidInfo)) {
            continue;
        }
        if (bundleNames.count(appAidInfo.element.GetBundleName()) > 0) {
            DebugLog("The bundlename : %{public}s is in the bundleNames", appAidInfo.element.GetBundleName().c_str());
            continue;
        }
        bundleNames.insert(appAidInfo.element.GetBundleName());
        AbilityInfo ability;
        ability.name = appAidInfo.element.GetAbilityName();
        ability.bundleName = appAidInfo.element.GetBundleName();
        AppExecFwk::BundleInfo bundleInfo{};
        int32_t bundleInfoFlag = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY) |
                                 static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
                                 static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
        if (bundleMgrProxy == nullptr) {
            ErrorLog("bundleMgrProxy is nullptr!");
            break;
        }
        bundleMgrProxy->GetBundleInfoV9(
            ability.bundleName, bundleInfoFlag, bundleInfo, AppExecFwk::Constants::START_USERID);
        DebugLog("The bundlename : %{public}s,the labelId : %{public}d,the iconId : %{public}d",
            appAidInfo.element.GetBundleName().c_str(),
            bundleInfo.applicationInfo.labelId,
            bundleInfo.applicationInfo.iconId);
        if (bundleInfo.applicationInfo.labelId != 0 && bundleInfo.applicationInfo.iconId != 0) {
            ability.labelId = bundleInfo.applicationInfo.labelId;
            ability.iconId = bundleInfo.applicationInfo.iconId;
            paymentAbilityInfos.push_back(ability);
        }
    }
}

bool AppDataParser::IsHceAppFromVendor(const ElementName &elementName)
{
    std::vector<HceAppAidInfo> hceApps;
    GetHceAppsFromVendor(hceApps);
    for (auto &app : hceApps) {
        if (app.element.GetBundleName() == elementName.GetBundleName() &&
            app.element.GetAbilityName() == elementName.GetAbilityName()) {
            return true;
        }
    }
    return false;
}
#endif
bool AppDataParser::IsBundleInstalled(const std::string &bundleName)
{
    sptr<AppExecFwk::IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    if (bundleMgrProxy == nullptr) {
        ErrorLog("bundleMgrProxy is nullptr!");
        return false;
    }
    if (bundleName.empty()) {
        ErrorLog("bundle name is empty");
        return false;
    }
    AppExecFwk::BundleInfo bundleInfo;
    bool result = bundleMgrProxy->GetBundleInfo(bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT,
                                                bundleInfo, USER_ID);
    ErrorLog("get bundle %{public}s result %{public}d ", bundleName.c_str(), result);
    return result;
}
void AppDataParser::GetHceApps(std::vector<HceAppAidInfo> &hceApps)
{
    for (const HceAppAidInfo &appAidInfo : g_hceAppAndAidMap) {
        hceApps.push_back(appAidInfo);
    }
#ifdef VENDOR_APPLICATIONS_ENABLED
    GetHceAppsFromVendor(hceApps);
#endif
}

bool AppDataParser::IsPaymentApp(const AppDataParser::HceAppAidInfo &hceAppInfo)
{
    for (const AppDataParser::AidInfo &aidInfo : hceAppInfo.customDataAid) {
        if (KITS::KEY_PAYMENT_AID == aidInfo.name) {
            return true;
        }
    }
    return false;
}

bool AppDataParser::IsHceApp(const ElementName &elementName)
{
    for (const AppDataParser::HceAppAidInfo &appAidInfo : g_hceAppAndAidMap) {
        if (appAidInfo.element.GetBundleName() == elementName.GetBundleName() &&
            appAidInfo.element.GetAbilityName() == elementName.GetAbilityName()) {
            return true;
        }
    }
#ifdef VENDOR_APPLICATIONS_ENABLED
    return IsHceAppFromVendor(elementName);
#else
    return false;
#endif
}

void AppDataParser::GetPaymentAbilityInfos(std::vector<AbilityInfo> &paymentAbilityInfos)
{
    if (!appListInitDone_) {
        InfoLog("bundleMgr is null, try to init again.");
        InitAppList();
    }
    for (const AppDataParser::HceAppAidInfo &appAidInfo : g_hceAppAndAidMap) {
        if (!IsPaymentApp(appAidInfo)) {
            continue;
        }
        AbilityInfo ability;
        ability.name = appAidInfo.element.GetAbilityName();
        ability.bundleName = appAidInfo.element.GetBundleName();
        ability.labelId = appAidInfo.labelId;
        ability.iconId = appAidInfo.iconId;
        InfoLog("The bundlename : %{public}s,the labelId : %{public}d,the iconId : %{public}d",
                ability.bundleName.c_str(), ability.labelId, ability.iconId);
        paymentAbilityInfos.push_back(ability);
    }

    for (const AppDataParser::HceAppAidInfo &appAidInfo : g_offHostAppAndAidMap) {
        AbilityInfo ability;
        ability.name = appAidInfo.element.GetAbilityName();
        ability.bundleName = appAidInfo.element.GetBundleName();
        ability.labelId = appAidInfo.labelId;
        ability.iconId = appAidInfo.iconId;
        InfoLog("The bundlename : %{public}s,the labelId : %{public}d,the iconId : %{public}d",
                ability.bundleName.c_str(), ability.labelId, ability.iconId);
        paymentAbilityInfos.push_back(ability);
    }
#ifdef VENDOR_APPLICATIONS_ENABLED
    GetPaymentAbilityInfosFromVendor(paymentAbilityInfos);
#endif
}

bool AppDataParser::GetBundleInfo(AppExecFwk::BundleInfo &bundleInfo, const std::string &bundleName)
{
    if (bundleName.empty()) {
        InfoLog("sim bundle name is empty.");
        return false;
    }
    sptr<AppExecFwk::IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    if (bundleMgrProxy == nullptr) {
        ErrorLog("bundleMgrProxy is nullptr.");
        return false;
    }
    bool result = bundleMgrProxy->GetBundleInfo(bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT,
                                                bundleInfo, USER_ID);
    InfoLog("get bundle %{public}s result %{public}d ", bundleName.c_str(), result);
    if (!result) {
        ErrorLog("get bundle %{public}s failed ", bundleName.c_str());
        return false;
    }
    return true;
}

bool AppDataParser::IsSystemApp(uint32_t uid)
{
    sptr<AppExecFwk::IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    if (bundleMgrProxy == nullptr) {
        ErrorLog(" bundleMgrProxy is nullptr.");
        return false;
    }
    return bundleMgrProxy->CheckIsSystemAppByUid(uid);
}

std::string AppDataParser::GetBundleNameByUid(uint32_t uid)
{
    auto bundleMgr = GetBundleMgrProxy();
    if (bundleMgr == nullptr) {
        ErrorLog("bundleMgr is nullptr.");
        return std::string();
    }
    std::string bundleName;
    int ret = bundleMgr->GetNameForUid(uid, bundleName);
    if (ret == ERR_OK) {
        return bundleName;
    } else {
        ErrorLog("GetNameForUid failed, ret = %{public}d.", ret);
        return std::string();
    }
}
} // namespace NFC
} // namespace OHOS
