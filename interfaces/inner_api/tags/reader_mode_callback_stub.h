/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_READER_MODE_CALLBACK_STUB_H
#define OHOS_READER_MODE_CALLBACK_STUB_H

#include <shared_mutex>
#include "nfc_sdk_common.h"
#include "ireader_mode_callback.h"
#include "iremote_object.h"
#include "iremote_stub.h"
#include "taginfo_parcelable.h"

namespace OHOS {
namespace NFC {
namespace TAG {
class ReaderModeCallbackStub : public IRemoteStub<KITS::IReaderModeCallback> {
public:
    ReaderModeCallbackStub();
    virtual ~ReaderModeCallbackStub();
    static ReaderModeCallbackStub* GetInstance();
    KITS::ErrorCode RegReaderMode(const sptr<KITS::IReaderModeCallback> &callback);

    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    void OnTagDiscovered(KITS::TagInfoParcelable* tagInfo) override;
    int RemoteTagDiscovered(MessageParcel &data, MessageParcel &reply);
    sptr<KITS::IReaderModeCallback> callback_;
    std::shared_mutex callbackMutex;
    bool mRemoteDied;
};
}  // namespace TAG
}  // namespace NFC
}  // namespace OHOS
#endif