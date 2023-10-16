﻿/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#ifndef TAG_DISPATCH_H
#define TAG_DISPATCH_H
#include <map>
#include <mutex>
#include "infc_service.h"
#include "itag_host.h"
#include "taginfo.h"
#include "taginfo_parcelable.h"

namespace OHOS {
namespace NFC {
class INfcService;
namespace TAG {
class TagDispatcher final {
public:
    explicit TagDispatcher(std::shared_ptr<INfcService> nfcService);
    ~TagDispatcher();
    TagDispatcher(const TagDispatcher&) = delete;
    TagDispatcher& operator=(const TagDispatcher&) = delete;

    int HandleTagFound(std::shared_ptr<NCI::ITagHost> tag);
    void HandleTagDebounce();
    std::weak_ptr<NCI::ITagHost> FindTagHost(int rfDiscId);

protected:
    std::shared_ptr<NCI::ITagHost> FindAndRemoveTagHost(int rfDiscId);
    void RegisterTagHost(std::shared_ptr<NCI::ITagHost> tag);
    void UnregisterTagHost(int rfDiscId);

private:
    std::shared_ptr<KITS::TagInfo> GetTagInfoFromTag(std::shared_ptr<NCI::ITagHost> tag);
    KITS::TagInfoParcelable GetTagInfoParcelableFromTag(std::shared_ptr<NCI::ITagHost> tag);
    void DispatchTag(std::shared_ptr<NCI::ITagHost> tag);
    void TagDisconnectedCallback(int tagRfDiscId);
    std::shared_ptr<INfcService> nfcService_ {};
    std::mutex mutex_ {};
    std::map<int, std::shared_ptr<NCI::ITagHost>> tagHostMap_ {};

    // tag field on checking
    const static int DEFAULT_FIELD_ON_CHECK_DURATION = 125; // ms
    const static int DEFAULT_ISO_DEP_FIELD_ON_CHECK_DURATION = 500; // ms

    // ndef message
    std::string lastNdefMsg_;
};
}  // namespace TAG
}  // namespace NFC
}  // namespace OHOS
#endif  // TAG_DISPATCH_H