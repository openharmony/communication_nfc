﻿/*
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

#ifndef NFC_NOTIFICATION_H
#define NFC_NOTIFICATION_H

#include <mutex>
#include <string>

#include "image_source.h"
#include "pixel_map.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

typedef void (*NfcNtfCallback)(int notificationId);
void RegNotificationCallback(NfcNtfCallback callback);
void PublishNfcNotification(int notificationId, const std::string &name, int balance);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

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

const int MAX_BUFF_LEN = 500;
const int NFC_UNIT_CHANGE_CONSTANT = 100;
const int NTF_AUTO_DELETE_TIME = 10000;
const int MAX_RES_VEC_LEN = 100;
const int NTF_COUNT_CONSTANT = 1000000; // final notification id = 1000000 * count + NfcNotificationId
const int NFC_MAX_NTF_COUNT = 100;
const int NFC_SERVICE_UID = 1027;

// use this flag to control notification banners
// 1 << 9 represents turning on the banner switch for System Ability.
// 0b010000 represents no vibration
const int NFC_NTF_CONTROL_FLAG = 1 << 9 | 0b010000; // no vibration

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

class NfcNotification {
public:
    static NfcNotification& GetInstance(void);

    void PublishNfcNotification(int notificationId, const std::string &name, int balance);
    void RegNotificationCallback(NfcNtfCallback callback);

private:
    NfcNotification();
    ~NfcNotification();
    NfcNotification(const NfcNotification&) = delete;
    NfcNotification& operator=(const NfcNotification&) = delete;

    void GetPixelMap(const std::string &path);

    std::mutex mutex_ {};
    std::shared_ptr<Media::PixelMap> nfcIconPixelMap_ {};
    std::vector<int> tagNtfCountVec_ {};
};
}  // namespace TAG
}  // namespace NFC
}  // namespace OHOS
#endif  // NFC_NOTIFICATION_H
