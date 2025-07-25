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

#include "nfc_notification.h"

#include <map>
#include <set>

#include "cJSON.h"
#include "file_ex.h"
#include "locale_config.h"
#include "locale_info.h"
#include "loghelper.h"
#include "nfc_sdk_common.h"
#include "securec.h"
#include "want_agent_helper.h"
#include "want_agent_info.h"

#ifdef DEBUG
#undef DEBUG
#endif
#include "notification_helper.h"

namespace OHOS {
namespace NFC {
namespace TAG {
enum NfcNotificationId : int {
    NFC_TAG_DEFAULT_NTF_ID = 114000,
    NFC_BT_NOTIFICATION_ID = 114001,
    NFC_WIFI_NOTIFICATION_ID = 114002,
    NFC_TRANSPORT_CARD_NOTIFICATION_ID = 114003,
    NFC_BROWSER_NOTIFICATION_ID = 114004,
    NFC_HCE_AID_CONFLICTED_ID = 114005,
    NFC_NO_HAP_SUPPORTED_NOTIFICATION_ID = 114006,

    // add NTF ID type before NFC_NTF_END
    NFC_NTF_END,
};

const std::set<int> NFC_NTF_ID_WHITELIST = {
    NFC_BT_NOTIFICATION_ID,
    NFC_WIFI_NOTIFICATION_ID,
    NFC_TRANSPORT_CARD_NOTIFICATION_ID
};

const int MAX_BUFF_LEN = 500;
const int NFC_UNIT_CHANGE_CONSTANT = 100;
const int NTF_AUTO_DELETE_TIME = 10000;
const int MAX_RES_VEC_LEN = 100;
const int NFC_SERVICE_UID = 1027;

// use this flag to control notification banners
// bit 4 represents vibration control: 1-off, 0-on
// bit 0 represents voice control: 1-off, 0-on
const uint32_t NFC_NTF_CONTROL_FLAG = 1 << 4 | 1;
// 1 << 9 represents turning on the banner switch for System Ability.
const uint32_t NFC_NTF_BANNER_SWITCH = 1 << 9;

constexpr const char* NFC_ICON_PATH = "system/etc/nfc/resources/base/media/nfc_icon.png";
constexpr const char* NFC_LANGUAGE_MAP_PATH = "system/etc/nfc/resources/base/profile/nfc_language_map.json";
constexpr const char* NFC_DEFAULT_LANGUAGE_FILE_PATH = "zh_CN";
constexpr const char* NFC_LANGUAGE_FILEPATH_PREFIX = "system/etc/nfc/resources/";
constexpr const char* NFC_LANGUAGE_FILEPATH_SUFFIX = "/element/string.json";
constexpr const char* NFC_ZHTW_LANGUAGE_FILE_PATH = "zh_TW";
constexpr const char* NFC_ZHHANT_LANGUAGE_FILE_PATH = "zh-Hant";  // The language type is Traditional Chinese
constexpr const char* NFC_ZHTW_REGION = "TW";

constexpr const char* KEY_LANGUAGE_MAP = "nfc_language_map";
constexpr const char* KEY_SYSTEM_LANGUAGE = "system_language";
constexpr const char* KEY_FILE_PATH = "file_path";

constexpr const char* KEY_STRING = "string";
constexpr const char* KEY_NAME = "name";
constexpr const char* KEY_VALUE = "value";

constexpr const char* KEY_TAG_DEFAULT_NTF_TITLE     = "DefaultTitle";
constexpr const char* KEY_TAG_DEFAULT_NTF_TEXT      = "DefaultText";
constexpr const char* KEY_TRANSPORT_CARD_NTF_TITLE  = "TransportCardTitle";
constexpr const char* KEY_TRANSPORT_CARD_NTF_TEXT   = "TransportCardText";
constexpr const char* KEY_NFC_WIFI_NTF_TITLE        = "NfcWifiNtfTitle";
constexpr const char* KEY_NFC_WIFI_NTF_TEXT         = "NfcWifiNtfText";
constexpr const char* KEY_ACTION_BUTTON_NAME        = "ActionButtonName";
constexpr const char* KEY_NFC_WIFI_BUTTON_NAME      = "NfcWifiButtonName";
constexpr const char* KEY_NFC_BT_NTF_TITLE          = "NfcBtNtfTitle";
constexpr const char* KEY_NFC_BT_NTF_TEXT           = "NfcBtNtfText";
constexpr const char* KEY_NFC_BT_BUTTON_NAME        = "NfcBtButtonName";
constexpr const char* NFC_OPEN_LINK_BUTTON_NAME     = "NfcOpenLinkButtonName";
constexpr const char* NFC_OPEN_LINK_TEXT_HEAD       = "NfcOpenLinkTextHead";
constexpr const char* KEY_HCE_AID_CONFLICTED_TITLE  = "NfcHceAidConflictedTitle";
constexpr const char* KEY_HCE_AID_CONFLICTED_TEXT   = "NfcHceAidConflictedText";
constexpr const char* KEY_NO_HAP_TITLE              = "NoHapSupportedNtfTitle";
constexpr const char* KEY_NO_HAP_TEXT               = "NoHapSupportedNtfText";
constexpr const char* KEY_NO_HAP_BUTTON_NAME        = "NoHapSupportedNtfButtonName";

static std::string g_sysLanguage = "";
static std::string g_sysRegion = "";
static std::map<std::string, std::string> g_resourceMap;
static std::mutex g_callbackMutex {};
static NfcNtfCallback g_ntfCallback = nullptr;

class NfcNotificationSubscriber : public Notification::NotificationSubscriber {
    void OnConnected() {}
    void OnDisconnected() {}
    void OnUpdate(const std::shared_ptr<Notification::NotificationSortingMap> &sortingMap) {}
    void OnDoNotDisturbDateChange(const std::shared_ptr<Notification::NotificationDoNotDisturbDate> &date) {}
    void OnEnabledNotificationChanged(
        const std::shared_ptr<Notification::EnabledNotificationCallbackData> &callbackData) {}
    void OnDied() {}
    void OnCanceled(const std::shared_ptr<OHOS::Notification::Notification> &request,
        const std::shared_ptr<Notification::NotificationSortingMap> &sortingMap, int deleteReason)
    {
        int creatorUid = request->GetUid();
        int notificationId = request->GetId();
        InfoLog("Oncanceled, creatorUid = %{public}d, notificationId = %{public}d, deleteReason = %{public}d",
            creatorUid, notificationId, deleteReason);

        std::lock_guard<std::mutex> lock(g_callbackMutex);
        if (deleteReason == Notification::NotificationConstant::CLICK_REASON_DELETE && g_ntfCallback) {
            g_ntfCallback(notificationId);
        }
    }
    void OnConsumed(const std::shared_ptr<OHOS::Notification::Notification> &notification,
        const std::shared_ptr<Notification::NotificationSortingMap> &sortingMap) {}
    void OnBadgeChanged(const std::shared_ptr<Notification::BadgeNumberCallbackData> &badgeData) {}
    void OnBadgeEnabledChanged(const sptr<Notification::EnabledNotificationCallbackData> &callbackData) {}
    void OnBatchCanceled(const std::vector<std::shared_ptr<OHOS::Notification::Notification>> &requestList,
        const std::shared_ptr<Notification::NotificationSortingMap> &sortingMap, int32_t deleteReason) {}
};

static std::shared_ptr<NfcNotificationSubscriber> g_notificationSubscriber
    = std::make_shared<NfcNotificationSubscriber>();

static void UpdateResourceMap(const std::string &resourcePath)
{
    InfoLog("Reading resource string from json config.");

    std::string content;
    LoadStringFromFile(resourcePath, content);
    cJSON *json = cJSON_Parse(content.c_str());
    if (json == nullptr) {
        ErrorLog("json nullptr.");
        return;
    }

    cJSON *resJson = cJSON_GetObjectItemCaseSensitive(json, KEY_STRING);
    if (resJson == nullptr || cJSON_GetArraySize(resJson) > MAX_RES_VEC_LEN) {
        ErrorLog("fail to parse res json");
        cJSON_Delete(json);
        return;
    }

    g_resourceMap.clear();
    cJSON *resJsonEach = nullptr;
    cJSON_ArrayForEach(resJsonEach, resJson) {
        cJSON *key = cJSON_GetObjectItemCaseSensitive(resJsonEach, KEY_NAME);
        if (key == nullptr || !cJSON_IsString(key)) {
            ErrorLog("json param not string");
            cJSON_Delete(json);
            return;
        }

        cJSON *value = cJSON_GetObjectItemCaseSensitive(resJsonEach, KEY_VALUE);
        if (value == nullptr || !cJSON_IsString(value)) {
            ErrorLog("json param not string");
            cJSON_Delete(json);
            return;
        }

        g_resourceMap.insert(std::pair<std::string, std::string>(key->valuestring, value->valuestring));
    }
    cJSON_Delete(json);
}

static std::string GetLanguageFilePath(const std::string &sysLanguage, const std::string &sysRegion)
{
    InfoLog("Reading language file path from json config.");
    std::string content;
    std::string filePath = NFC_DEFAULT_LANGUAGE_FILE_PATH;
    LoadStringFromFile(NFC_LANGUAGE_MAP_PATH, content);
    cJSON *json = cJSON_Parse(content.c_str());
    if (json == nullptr) {
        ErrorLog("json nullptr.");
        return filePath;
    }

    cJSON *resJson = cJSON_GetObjectItemCaseSensitive(json, KEY_LANGUAGE_MAP);
    if (resJson == nullptr || !cJSON_IsArray(resJson)) {
        ErrorLog("fail to parse KEY_LANGUAGE_MAP");
        cJSON_Delete(json);
        return filePath;
    }

    if (sysLanguage == NFC_ZHHANT_LANGUAGE_FILE_PATH && sysRegion == NFC_ZHTW_REGION) {
        cJSON_Delete(json);
        InfoLog("file path is zh-TW");
        return NFC_ZHTW_LANGUAGE_FILE_PATH;
    }

    cJSON *resJsonEach = nullptr;
    cJSON_ArrayForEach(resJsonEach, resJson) {
        cJSON *key = cJSON_GetObjectItemCaseSensitive(resJsonEach, KEY_SYSTEM_LANGUAGE);
        if (key == nullptr || !cJSON_IsString(key)) {
            ErrorLog("json param KEY_SYSTEM_LANGUAGE not string");
            continue;
        }
        if (key->valuestring != sysLanguage) {
            continue;
        }

        cJSON *value = cJSON_GetObjectItemCaseSensitive(resJsonEach, KEY_FILE_PATH);
        if (value == nullptr || !cJSON_IsString(value)) {
            ErrorLog("json param KEY_FILE_PATH not string");
            cJSON_Delete(json);
            return filePath;
        }

        filePath = value->valuestring;
        break;
    }
    cJSON_Delete(json);
    InfoLog("file path %{public}s", filePath.c_str());
    return filePath;
}

static void UpdateResourceMapByLanguage()
{
    std::string curSysLanguage = Global::I18n::LocaleConfig::GetSystemLanguage();
    std::string curSysRegion = Global::I18n::LocaleConfig::GetSystemRegion();
    if (g_sysLanguage == curSysLanguage && curSysRegion == g_sysRegion) {
        DebugLog("same language environment[%{public}s], region[%{public}s] ,no need to update resource map.",
                 curSysLanguage.c_str(), curSysRegion.c_str());
        return;
    }

    InfoLog("current system language[%{public}s], region[%{public}s] changes, should update resource map",
            curSysLanguage.c_str(), curSysRegion.c_str());
    g_sysLanguage = curSysLanguage;
    g_sysRegion = curSysRegion;

    std::string filePath = NFC_LANGUAGE_FILEPATH_PREFIX +
                        GetLanguageFilePath(g_sysLanguage, g_sysRegion) +
                        NFC_LANGUAGE_FILEPATH_SUFFIX;
    UpdateResourceMap(filePath);
}

static std::string GetTrafficCardNotificationText(const std::string &cardName, int balance)
{
    char buf[MAX_BUFF_LEN] = {0};
    int ret = sprintf_s(buf, MAX_BUFF_LEN, g_resourceMap[KEY_TRANSPORT_CARD_NTF_TEXT].c_str(),
        g_resourceMap[cardName].c_str(), static_cast<float>(balance) / NFC_UNIT_CHANGE_CONSTANT);
    if (ret <= 0) {
        ErrorLog("sprintf_s failed, ret[%{public}d]", ret);
        return "";
    }

    return std::string(buf);
}

#ifdef NDEF_WIFI_ENABLED
static std::string GetWifiNotificationText(const std::string &ssid)
{
    char buf[MAX_BUFF_LEN] = {0};
    int ret = sprintf_s(buf, MAX_BUFF_LEN, g_resourceMap[KEY_NFC_WIFI_NTF_TEXT].c_str(), ssid.c_str());
    if (ret <= 0) {
        ErrorLog("sprintf_s failed, ret[%{public}d]", ret);
        return "";
    }

    return std::string(buf);
}
#endif

#ifdef NDEF_BT_ENABLED
static std::string GetBtNotificationText(const std::string &name)
{
    char buf[MAX_BUFF_LEN] = {0};
    int ret = sprintf_s(buf, MAX_BUFF_LEN, g_resourceMap[KEY_NFC_BT_NTF_TEXT].c_str(), name.c_str());
    if (ret <= 0) {
        ErrorLog("sprintf_s failed, ret[%{public}d]", ret);
        return "";
    }

    return std::string(buf);
}
#endif

static bool SetTitleAndTextForOtherNotificationId(int notificationId,
    std::shared_ptr<Notification::NotificationNormalContent> nfcContent, const std::string &name, int balance)
{
    switch (notificationId) {
        case NFC_TAG_DEFAULT_NTF_ID:
            if (g_resourceMap.find(KEY_TAG_DEFAULT_NTF_TITLE) != g_resourceMap.end() &&
                g_resourceMap.find(KEY_TAG_DEFAULT_NTF_TEXT) != g_resourceMap.end()) {
                nfcContent->SetTitle(g_resourceMap[KEY_TAG_DEFAULT_NTF_TITLE]);
                nfcContent->SetText(g_resourceMap[KEY_TAG_DEFAULT_NTF_TEXT]);
            }
            break;
        case NFC_BROWSER_NOTIFICATION_ID:
            if (g_resourceMap.find(KEY_TAG_DEFAULT_NTF_TITLE) != g_resourceMap.end() &&
                g_resourceMap.find(NFC_OPEN_LINK_TEXT_HEAD) != g_resourceMap.end()) {
                nfcContent->SetTitle(g_resourceMap[KEY_TAG_DEFAULT_NTF_TITLE]);
                nfcContent->SetText(g_resourceMap[NFC_OPEN_LINK_TEXT_HEAD] + name);
            }
            break;
        case NFC_HCE_AID_CONFLICTED_ID:
            if (g_resourceMap.find(KEY_HCE_AID_CONFLICTED_TITLE) != g_resourceMap.end() &&
                g_resourceMap.find(KEY_HCE_AID_CONFLICTED_TEXT) != g_resourceMap.end()) {
                nfcContent->SetTitle(g_resourceMap[KEY_HCE_AID_CONFLICTED_TITLE]);
                nfcContent->SetText(g_resourceMap[KEY_HCE_AID_CONFLICTED_TEXT]);
            }
            break;
        case NFC_NO_HAP_SUPPORTED_NOTIFICATION_ID:
            if (g_resourceMap.find(KEY_NO_HAP_TITLE) != g_resourceMap.end() &&
                g_resourceMap.find(KEY_NO_HAP_TEXT) != g_resourceMap.end()) {
                nfcContent->SetTitle(g_resourceMap[KEY_NO_HAP_TITLE]);
                nfcContent->SetText(g_resourceMap[KEY_NO_HAP_TEXT]);
            }
            break;
        default:
            WarnLog("unknown notification ID");
            return false;
    }
    return true;
}

static bool SetTitleAndText(int notificationId,
    std::shared_ptr<Notification::NotificationNormalContent> nfcContent, const std::string &name, int balance)
{
    if (nfcContent == nullptr) {
        ErrorLog("notification normal content nullptr");
        return false;
    }
    UpdateResourceMapByLanguage();

    switch (notificationId) {
        case NFC_TRANSPORT_CARD_NOTIFICATION_ID:
            if (g_resourceMap.find(KEY_TRANSPORT_CARD_NTF_TITLE) != g_resourceMap.end() &&
                g_resourceMap.find(KEY_TRANSPORT_CARD_NTF_TEXT) != g_resourceMap.end() &&
                g_resourceMap.find(name) != g_resourceMap.end()) {
                nfcContent->SetTitle(g_resourceMap[KEY_TRANSPORT_CARD_NTF_TITLE]);
                nfcContent->SetText(GetTrafficCardNotificationText(name, balance));
            }
            break;
        case NFC_WIFI_NOTIFICATION_ID:
#ifdef NDEF_WIFI_ENABLED
            if (g_resourceMap.find(KEY_NFC_WIFI_NTF_TITLE) != g_resourceMap.end() &&
                g_resourceMap.find(KEY_NFC_WIFI_NTF_TEXT) != g_resourceMap.end()) {
                nfcContent->SetTitle(g_resourceMap[KEY_NFC_WIFI_NTF_TITLE]);
                nfcContent->SetText(GetWifiNotificationText(name));
            }
            break;
#else
            ErrorLog("nfc wifi notification not supported");
            return false;
#endif
        case NFC_BT_NOTIFICATION_ID:
#ifdef NDEF_BT_ENABLED
            if (g_resourceMap.find(KEY_NFC_BT_NTF_TITLE) != g_resourceMap.end() &&
                g_resourceMap.find(KEY_NFC_BT_NTF_TEXT) != g_resourceMap.end()) {
                nfcContent->SetTitle(g_resourceMap[KEY_NFC_BT_NTF_TITLE]);
                nfcContent->SetText(GetBtNotificationText(name));
            }
            break;
#else
            ErrorLog("nfc bt notification not supported");
            return false;
#endif
        default:
            return SetTitleAndTextForOtherNotificationId(notificationId, nfcContent, name, balance);
    }
    return true;
}

static std::string GetButtonName(int notificationId)
{
    switch (notificationId) {
        case NFC_BT_NOTIFICATION_ID:
            if (g_resourceMap.find(KEY_NFC_BT_BUTTON_NAME) != g_resourceMap.end()) {
                return g_resourceMap[KEY_NFC_BT_BUTTON_NAME];
            }
            return "";
        case NFC_WIFI_NOTIFICATION_ID:
            if (g_resourceMap.find(KEY_NFC_WIFI_BUTTON_NAME) != g_resourceMap.end()) {
                return g_resourceMap[KEY_NFC_WIFI_BUTTON_NAME];
            }
            return "";
        case NFC_BROWSER_NOTIFICATION_ID:
            if (g_resourceMap.find(NFC_OPEN_LINK_BUTTON_NAME) != g_resourceMap.end()) {
                return g_resourceMap[NFC_OPEN_LINK_BUTTON_NAME];
            }
            return "";
        case NFC_NO_HAP_SUPPORTED_NOTIFICATION_ID:
            if (g_resourceMap.find(KEY_NO_HAP_BUTTON_NAME) != g_resourceMap.end()) {
                return g_resourceMap[KEY_NO_HAP_BUTTON_NAME];
            }
            return "";
        default:
            if (g_resourceMap.find(KEY_ACTION_BUTTON_NAME) != g_resourceMap.end()) {
                return g_resourceMap[KEY_ACTION_BUTTON_NAME];
            }
            return "";
    }
}

static void SetActionButton(const std::string& buttonName, Notification::NotificationRequest& request)
{
    auto want = std::make_shared<AAFwk::Want>();
    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    wants.push_back(want);
    std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> flags;
    flags.push_back(AbilityRuntime::WantAgent::WantAgentConstant::Flags::CONSTANT_FLAG);
    AbilityRuntime::WantAgent::WantAgentInfo wantAgentInfo(
        0, AbilityRuntime::WantAgent::WantAgentConstant::OperationType::UNKNOWN_TYPE,
        flags, wants, nullptr
    );
    auto wantAgentDeal = AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(wantAgentInfo);
    std::shared_ptr<Notification::NotificationActionButton> actionButtonDeal =
        Notification::NotificationActionButton::Create(nullptr, buttonName, wantAgentDeal);
    if (actionButtonDeal == nullptr) {
        ErrorLog("get notification actionButton nullptr");
        return;
    }
    request.AddActionButton(actionButtonDeal);
}

static int64_t GetAutoDeleteTime()
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return duration.count() + NTF_AUTO_DELETE_TIME;
}

static bool IsNtfIdWhiteList(int notificationId)
{
    return (NFC_NTF_ID_WHITELIST.find(notificationId) != NFC_NTF_ID_WHITELIST.end());
}

static void SetBasicOption(Notification::NotificationRequest &request, int notificationId, bool isNfcNotDisturb)
{
    request.SetCreatorUid(NFC_SERVICE_UID);
    request.SetAutoDeletedTime(GetAutoDeleteTime());
    request.SetTapDismissed(true);
    request.SetSlotType(OHOS::Notification::NotificationConstant::SlotType::SOCIAL_COMMUNICATION);

    uint32_t controlFlag = NFC_NTF_CONTROL_FLAG;
    if (!isNfcNotDisturb || IsNtfIdWhiteList(notificationId)) {
        InfoLog("turn on banner switch for NFC ntf.");
        controlFlag = NFC_NTF_BANNER_SWITCH;
    }
    InfoLog("controlFlag = 0x%{public}x", controlFlag);
    request.SetNotificationControlFlags(controlFlag);
}

static bool SetNfcRequestContent(
    Notification::NotificationRequest &request, int notificationId, const std::string &name, int balance)
{
    std::shared_ptr<Notification::NotificationNormalContent> nfcContent =
        std::make_shared<Notification::NotificationNormalContent>();
    if (nfcContent == nullptr) {
        ErrorLog("get notification normal content nullptr");
        return false;
    }

    if (!SetTitleAndText(notificationId, nfcContent, name, balance)) {
        ErrorLog("error setting title and text");
        return false;
    }
    std::shared_ptr<Notification::NotificationContent> content =
        std::make_shared<Notification::NotificationContent>(nfcContent);
    if (content == nullptr) {
        ErrorLog("get notification content nullptr");
        return false;
    }
    request.SetContent(content);
    return true;
}

void NfcNotification::GetPixelMap(const std::string &path)
{
    if (nfcIconPixelMap_ != nullptr) {
        InfoLog("nfc icon pixel map already exists.");
        return;
    }

    if (!std::filesystem::exists(path)) {
        ErrorLog("nfc icon file path not exists.");
        nfcIconPixelMap_ = nullptr;
        return;
    }
    uint32_t errorCode = 0;
    Media::SourceOptions opts;
    opts.formatHint = "image/png";
    std::unique_ptr<Media::ImageSource> imageSource = Media::ImageSource::CreateImageSource(path, opts, errorCode);
    if (imageSource == nullptr) {
        ErrorLog("imageSource nullptr");
        nfcIconPixelMap_ = nullptr;
        return;
    }
    Media::DecodeOptions decodeOpts;
    std::unique_ptr<Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    nfcIconPixelMap_ = std::move(pixelMap);
}

NfcNotification& NfcNotification::GetInstance()
{
    static NfcNotification instance;
    return instance;
}

NfcNotification::NfcNotification()
{
    InfoLog("NfcNotification constructor enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    // only need to subscribe notification once
    int result = Notification::NotificationHelper::SubscribeNotification(*g_notificationSubscriber);
    if (result != ERR_OK) {
        ErrorLog("fail to subscribe notification");
    }
    UpdateResourceMapByLanguage();
}

NfcNotification::~NfcNotification()
{
    InfoLog("NfcNotification destructor enter.");
    // no operation to unsubscribe notification
}

void NfcNotification::PublishNfcNotification(
    bool isNfcNotDisturb, int notificationId, const std::string &name, int balance)
{
    if (notificationId >= NFC_NTF_END || notificationId < NFC_TAG_DEFAULT_NTF_ID) {
        ErrorLog("invalid notification id.");
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    int ret = Notification::NotificationHelper::CancelAllNotifications();
    InfoLog("Cancel all ntf result[%{public}d]", ret);

    Notification::NotificationRequest request;
    SetBasicOption(request, notificationId, isNfcNotDisturb);
    if (!SetNfcRequestContent(request, notificationId, name, balance)) {
        ErrorLog("fail to set request content.");
        return;
    }
    request.SetNotificationId(notificationId);

    GetPixelMap(NFC_ICON_PATH);
    if (nfcIconPixelMap_ != nullptr) {
        request.SetLittleIcon(nfcIconPixelMap_);
        request.SetBadgeIconStyle(Notification::NotificationRequest::BadgeStyle::LITTLE);
    }

    std::string buttonName = GetButtonName(notificationId);
    if (!buttonName.empty()) {
        SetActionButton(buttonName, request);
    }

    ret = Notification::NotificationHelper::PublishNotification(request);
    InfoLog("NFC service publish notification result = %{public}d", ret);
}

void NfcNotification::RegNotificationCallback(NfcNtfCallback callback)
{
    std::lock_guard<std::mutex> lock(g_callbackMutex);
    g_ntfCallback = callback;
}
}  // namespace TAG
}  // namespace NFC
}  // namespace OHOS

void RegNotificationCallback(NfcNtfCallback callback)
{
    OHOS::NFC::TAG::NfcNotification::GetInstance().RegNotificationCallback(callback);
}

void PublishNfcNotification(bool isNfcNotDisturb, int notificationId, const std::string &name, int balance)
{
    InfoLog("Publishing nfc tag notification, id [%{public}d]", notificationId);
    OHOS::NFC::TAG::NfcNotification::GetInstance().PublishNfcNotification(
        isNfcNotDisturb, notificationId, name, balance);
}