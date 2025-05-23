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

#ifndef NFC_NAPI_TAG_NDEF_H_
#define NFC_NAPI_TAG_NDEF_H_

#include <locale>
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "ndef_tag.h"
#include "ndef_message.h"
#include "nfc_napi_ndef_message.h"
#include "nfc_napi_tag_session.h"
#include "nfc_napi_common_utils.h"

namespace OHOS {
namespace NFC {
namespace KITS {
struct NapiNdefTag : public NapiNfcTagSession {
    static napi_value RegisterNdefMessageJSClass(napi_env env, napi_value exports);
    static napi_value CreateNdefMessage(napi_env env, napi_callback_info info);
    static napi_value GetNdefTagType(napi_env env, napi_callback_info info);
    static napi_value GetNdefMessage(napi_env env, napi_callback_info info);
    static napi_value IsNdefWritable(napi_env env, napi_callback_info info);
    static napi_value ReadNdef(napi_env env, napi_callback_info info);
    static napi_value WriteNdef(napi_env env, napi_callback_info info);
    static napi_value CanSetReadOnly(napi_env env, napi_callback_info info);
    static napi_value SetReadOnly(napi_env env, napi_callback_info info);
    static napi_value GetNdefTagTypeString(napi_env env, napi_callback_info info);
};

template<typename T, typename D>
struct NdefContext : BaseContext {
    T value;
    D *objectInfo;
    std::shared_ptr<NdefMessage> msg;
};
} // namespace KITS
} // namespace NFC
} // namespace OHOS
#endif