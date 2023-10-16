/*
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
#ifndef NFC_EVENT_HANDLER_H
#define NFC_EVENT_HANDLER_H
#include "common_event_manager.h"
#include "event_handler.h"
#include "infcc_host.h"
#include "nfc_service.h"
#include "tag_dispatcher.h"

namespace OHOS {
namespace NFC {
class NfcEventHandler final : public AppExecFwk::EventHandler {
public:
    explicit NfcEventHandler(const std::shared_ptr<AppExecFwk::EventRunner>& runner,
                                std::weak_ptr<NfcService> servcie);
    ~NfcEventHandler();
    NfcEventHandler& operator=(const NfcEventHandler&) = delete;
    NfcEventHandler(const NfcEventHandler&) = delete;

    void Intialize(std::weak_ptr<TAG::TagDispatcher> tagDispatcher, std::weak_ptr<CeService> ceService);
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer& event) override;

    void SubscribeScreenChangedEvent();
    void SubscribePackageChangedEvent();

protected:
    // Screen Changed Receiver
    class ScreenChangedReceiver;
    // Package Changed Receiver；
    class PackageChangedReceiver;

private:
    std::shared_ptr<EventFwk::CommonEventSubscriber> screenSubscriber_ {};
    std::shared_ptr<EventFwk::CommonEventSubscriber> pkgSubscriber_ {};

    std::weak_ptr<NfcService> nfcService_ {};
    std::weak_ptr<TAG::TagDispatcher> tagDispatcher_ {};
    std::weak_ptr<CeService> ceService_ {};
};
}  // namespace NFC
}  // namespace OHOS
#endif  // NFC_EVENT_HANDLER_H