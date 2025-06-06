/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "ndef_har_dispatch.h"

#include "external_deps_proxy.h"
#include "iservice_registry.h"
#include "ndef_har_data_parser.h"
#include "tag_ability_dispatcher.h"
#include "ability_manager_client.h"
#include "loghelper.h"
#include "bundle_mgr_interface.h"
#include "if_system_ability_manager.h"
#ifdef NFC_HANDLE_SCREEN_LOCK
#include "external_deps_proxy.h"
#include "screenlock_common.h"
#include "power_mgr_client.h"
#include "nfc_sdk_common.h"
#endif
namespace OHOS {
namespace NFC {
namespace TAG {
const int USER_ID = 100;
const int BUNDLE_MGR_SERVICE_SYS_ABILITY_ID = 401;
using namespace OHOS::NFC::KITS;
#ifdef NFC_HANDLE_SCREEN_LOCK
AAFwk::Want g_carrierWant;
static std::mutex g_isCarrierModeMutex {};
static bool g_isCarrierMode = false;
uint64_t g_lastCarrierReportTime;
const int SET_UNLOCK_TIMEOUT = 30 * 1000;
#endif
std::string uri_ {};
std::string browserBundleName_ {};

#ifdef NFC_HANDLE_SCREEN_LOCK
NfcUnlockScreenCallback::NfcUnlockScreenCallback() {}
NfcUnlockScreenCallback::~NfcUnlockScreenCallback() {}

void NfcUnlockScreenCallback::OnCallBack(const int32_t screenLockResult)
{
    InfoLog("NfcUnlockScreenCallback OnCallBack enabled. screenLockResult = %{public}d.", screenLockResult);
}
#endif

NdefHarDispatch::NdefHarDispatch(std::weak_ptr<NCI::INciNfccInterface> nciNfccProxy)
    : nciNfccProxy_(nciNfccProxy)
{
}

sptr<AppExecFwk::IBundleMgr> NdefHarDispatch::GetBundleMgrProxy()
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
    return iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
}

/* Implicit matching, using mimetype to pull up app */
bool NdefHarDispatch::DispatchMimeType(const std::string &type, const std::shared_ptr<KITS::TagInfo> &tagInfo)
{
    if (type.empty() || tagInfo == nullptr) {
        ErrorLog("NdefHarDispatch::DispatchMimeType type is empty");
        return false;
    }
    AAFwk::Want want;
    want.SetType(type);
    ExternalDepsProxy::GetInstance().SetWantExtraParam(tagInfo, want);
    if (GetBundleMgrProxy() == nullptr) {
        ErrorLog("NdefHarDispatch::DispatchMimeType GetBundleMgrProxy is nullptr");
        return false;
    }
    bool withDefault = false;
    auto abilityInfoFlag = AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_DEFAULT
        | AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_SKILL_URI
        | AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_METADATA;
    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool findDefaultApp = false;
    if (!GetBundleMgrProxy()->ImplicitQueryInfos(
        want, abilityInfoFlag, USER_ID, withDefault, abilityInfos, extensionInfos, findDefaultApp)) {
        ErrorLog("NdefHarDispatch::DispatchMimeType ImplicitQueryInfos false");
        return false;
    }
    int32_t errCode = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    if (errCode) {
        ErrorLog("NdefHarDispatch::DispatchMimeType call StartAbility fail. ret = %{public}d", errCode);
        return false;
    }
    ExternalDepsProxy::GetInstance().WriteDispatchToAppHiSysEvent(want.GetElement().GetBundleName(),
        SubErrorCode::NDEF_HAR_DISPATCH);
    return true;
}

/* Verify harPackageString as BundleName/ServiceName and call StartExtensionAbility to pull up app */
bool NdefHarDispatch::DispatchBundleExtensionAbility(const std::string &harPackageString,
    const std::shared_ptr<KITS::TagInfo> &tagInfo, const std::string &mimeType, const std::string &uri)
{
    std::istringstream iss(harPackageString);
    std::string bundleName;
    std::string serviceName;
    if (!getline(iss, bundleName, '/')) {
        InfoLog("harPackageString bundleName invalid");
        return false;
    }
    if (!getline(iss, serviceName, '/')) {
        InfoLog("harPackageString serviceName invalid");
        return false;
    }
    AAFwk::Want want;
    want.SetElementName(bundleName, serviceName);
    if (!mimeType.empty()) {
        want.SetType(mimeType);
    }
    if (uri.size() > 0) {
        want.SetUri(uri);
    }
    if (tagInfo != nullptr) {
        ExternalDepsProxy::GetInstance().SetWantExtraParam(tagInfo, want);
    }
    int errCode = AAFwk::AbilityManagerClient::GetInstance()->StartExtensionAbility(want, nullptr);
    InfoLog("StartExtensionAbility ret = %{public}d, bundleName = %{public}s, serviceName = %{public}s", errCode,
        bundleName.c_str(), serviceName.c_str());
    return (errCode == 0);
}

/* Call GetLaunchWantForBundle through bundlename to obtain the want and pull up the app */
bool NdefHarDispatch::DispatchBundleAbility(const std::string &harPackage,
    const std::shared_ptr<KITS::TagInfo> &tagInfo, const std::string &mimeType, const std::string &uri,
    OHOS::sptr<IRemoteObject> tagServiceIface)
{
    if (harPackage.empty()) {
        ErrorLog("NdefHarDispatch::DispatchBundleAbility harPackage is empty");
        return false;
    }
    std::string harPackageString = NfcSdkCommon::HexStringToAsciiString(harPackage);
    AAFwk::Want want;
    if (GetBundleMgrProxy() == nullptr) {
        ErrorLog("GetBundleMgrProxy is nullptr");
        return false;
    }
    int32_t errCode = GetBundleMgrProxy()->GetLaunchWantForBundle(harPackageString, want, USER_ID);
    if (errCode) {
        InfoLog("GetLaunchWantForBundle fail. ret = %{public}d, harPackage = %{public}s, try ExtensionAbility instead",
            errCode, harPackageString.c_str());
        if (DispatchBundleExtensionAbility(harPackageString, tagInfo, mimeType, uri)) {
            return true;
        }
        return false;
    }
    if (!mimeType.empty()) {
        want.SetType(mimeType);
    }
    if (tagServiceIface == nullptr) {
        WarnLog("tagServiceIface is null");
    }
    if (tagInfo != nullptr) {
        want.SetParam("remoteTagService", tagServiceIface);
        ExternalDepsProxy::GetInstance().SetWantExtraParam(tagInfo, want);
    }
    if (uri.size() > 0) {
        want.SetUri(uri);
    }
    if (!nciNfccProxy_.expired()) {
        nciNfccProxy_.lock()->UpdateWantExtInfoByVendor(want, uri);
    }
#ifdef NFC_HANDLE_SCREEN_LOCK
    auto screenLockIface = ScreenLock::ScreenLockManager::GetInstance();
    if (screenLockIface == nullptr) {
        ErrorLog("ScreenLock::ScreenLockManager interface invalid");
        return false;
    }
    bool isLocked = false;
    screenLockIface->IsLocked(isLocked);
    if (isLocked) {
        g_carrierWant = want;
        sptr<NfcUnlockScreenCallback> listener = new (std::nothrow) NfcUnlockScreenCallback();
        if (listener == nullptr) {
            ErrorLog("NfcUnlockScreenCallback listener invalid");
            return false;
        }
        screenLockIface->Unlock(ScreenLock::Action::UNLOCKSCREEN, listener);
        g_lastCarrierReportTime = KITS::NfcSdkCommon::GetCurrentTime();
        g_isCarrierMode = true;
        ExternalDepsProxy::GetInstance().StartVibratorOnce();
        return true;
    }
    if (!PowerMgr::PowerMgrClient::GetInstance().IsScreenOn()) {
        PowerMgr::PowerMgrClient::GetInstance().WakeupDevice();
    }
#endif
    errCode = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    if (errCode) {
        ErrorLog("StartAbility fail. ret = %{public}d, harPackage = %{public}s",
            errCode, harPackageString.c_str());
        return false;
    }
    ExternalDepsProxy::GetInstance().WriteDispatchToAppHiSysEvent(want.GetElement().GetBundleName(),
        SubErrorCode::NDEF_HAR_DISPATCH);
    if (!nciNfccProxy_.expired()) {
        nciNfccProxy_.lock()->NotifyMessageToVendor(KITS::TAG_DISPATCH_HAR_PACKAGE, harPackageString);
    }
    return true;
}

#ifdef NFC_HANDLE_SCREEN_LOCK
void NdefHarDispatch::HandleCarrierReport()
{
    InfoLog("NdefHarDispatch::HandleCarrierReport enter.");
    std::lock_guard<std::mutex> lock(g_isCarrierModeMutex);
    uint64_t currTime = KITS::NfcSdkCommon::GetCurrentTime();
    if ((currTime - g_lastCarrierReportTime) < SET_UNLOCK_TIMEOUT && g_isCarrierMode) {
        InfoLog("Unlock successfully before timeout.");
        auto abilityManagerClient = AAFwk::AbilityManagerClient::GetInstance();
        if (abilityManagerClient == nullptr) {
            g_isCarrierMode = false;
            ErrorLog("abilityManagerClient is nullptr.");
            return;
        }
        abilityManagerClient->StartAbility(g_carrierWant);
    }
    g_isCarrierMode = false;
}
#endif

bool NdefHarDispatch::DispatchUriToBundleAbility(const std::string &uri)
{
    if (uri.empty()) {
        ErrorLog("NdefHarDispatch::DispatchUriToBundleAbility uri is empty");
        return false;
    }
    bool canOpen = false;
    if (GetBundleMgrProxy() == nullptr) {
        ErrorLog("NdefHarDispatch::DispatchUriToBundleAbility GetBundleMgrProxy is nullptr");
        return false;
    }
    int32_t errCode = GetBundleMgrProxy()->CanOpenLink(uri, canOpen);
    if (!errCode && canOpen) {
        InfoLog("NdefHarDispatch::DispatchUriToBundleAbility CanOpenLink");
    }
    ErrorLog("CanOpenLink fail. errCode = %{public}d, canOpen = %{public}d", errCode, canOpen);
    return false;
}

/* If the corresponding app has been installed, the system jumps to the corresponding app and starts it.
 * If the corresponding app is not installed, the default browser is used to open the corresponding page.
 */
bool NdefHarDispatch::DispatchByAppLinkMode(const std::string &uriSchemeValue,
    const std::shared_ptr<KITS::TagInfo> &tagInfo, OHOS::sptr<IRemoteObject> tagServiceIface)
{
    std::unique_lock<std::shared_mutex> guard(mutex_);
    InfoLog("enter");
    if (uriSchemeValue.empty()) {
        ErrorLog("uriSchemeValue is empty");
        return false;
    }
    if (tagInfo == nullptr) {
        ErrorLog("tagInfo is null");
        return false;
    }
    if (tagServiceIface == nullptr) {
        WarnLog("tagServiceIface is null");
    }
    AAFwk::Want want;
    const std::string PARAM_KEY = "appLinkingOnly"; // Use App Linking Mode
    want.SetUri(uriSchemeValue);
    want.SetParam(PARAM_KEY, false);
    want.SetParam("remoteTagService", tagServiceIface);
    ExternalDepsProxy::GetInstance().SetWantExtraParam(tagInfo, want);
    int32_t errCode = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    if (errCode) {
        ErrorLog(
            "call StartAbility fail. uriSchemeValue = [%{public}s] ret = %{public}d", uriSchemeValue.c_str(), errCode);
        return false;
    }
    ExternalDepsProxy::GetInstance().WriteDispatchToAppHiSysEvent(want.GetElement().GetBundleName(),
        SubErrorCode::NDEF_URI_BROWSER_DISPATCH);
    return true;
}
} // namespace TAG
} // namespace NFC
} // namespace OHOS