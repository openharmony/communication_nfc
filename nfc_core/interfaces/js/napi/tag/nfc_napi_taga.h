/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef NFC_NAPI_TAGA_H_
#define NFC_NAPI_TAGA_H_

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "nfc_napi_tag_sesstion.h"
#include "nfc_napi_utils.h"
#include "nfca_tag.h"

namespace OHOS {
namespace NFC {
namespace KITS {
struct NapiNfcATag : public NapiNfcTagSession {
    static napi_value GetSak(napi_env env, napi_callback_info info);
    static napi_value GetAtqa(napi_env env, napi_callback_info info);
};
} // namespace KITS
} // namespace NFC
} // namespace OHOS
#endif