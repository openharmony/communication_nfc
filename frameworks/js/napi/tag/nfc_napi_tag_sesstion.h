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

#ifndef NFC_NAPI_TAG_SESSTION_H_
#define NFC_NAPI_TAG_SESSTION_H_

#include <memory>
#include "basic_tag_session.h"
#include "napi/native_node_api.h"
#include "nfc_napi_utils.h"

namespace OHOS {
namespace NFC {
namespace KITS {
struct NapiNfcTagSession {
    static napi_value GetTagInfo(napi_env env, napi_callback_info info);
    static napi_value ConnectTag(napi_env env, napi_callback_info info);
    static napi_value Reset(napi_env env, napi_callback_info info);
    static napi_value IsTagConnected(napi_env env, napi_callback_info info);
    static napi_value SetSendDataTimeout(napi_env env, napi_callback_info info);
    static napi_value GetSendDataTimeout(napi_env env, napi_callback_info info);
    static napi_value SendData(napi_env env, napi_callback_info info);
    static napi_value GetMaxSendLength(napi_env env, napi_callback_info info);
    std::shared_ptr<BasicTagSession> tagSession = nullptr;
};
} // namespace KITS
} // namespace NFC
} // namespace OHOS
#endif