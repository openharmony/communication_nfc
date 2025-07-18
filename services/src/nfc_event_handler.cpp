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
#include "nfc_event_handler.h"

#include "ce_service.h"
#include "common_event_support.h"
#include "loghelper.h"
#include "nfc_service.h"
#include "nfc_polling_manager.h"
#include "nfc_routing_manager.h"
#include "want.h"
#include "screenlock_manager.h"
#include "power_mgr_client.h"
#include "nfc_watch_dog.h"

#ifdef NDEF_WIFI_ENABLED
#include "wifi_connection_manager.h"
#endif
#ifdef NDEF_BT_ENABLED
#include "bt_connection_manager.h"
#endif
#ifdef NFC_HANDLE_SCREEN_LOCK
#include "ndef_har_dispatch.h"
#endif

namespace OHOS {
namespace NFC {
const std::string EVENT_DATA_SHARE_READY = "usual.event.DATA_SHARE_READY";

class NfcEventHandler::ScreenChangedReceiver : public EventFwk::CommonEventSubscriber {
public:
    explicit ScreenChangedReceiver(std::weak_ptr<NfcService> nfcService,
        const EventFwk::CommonEventSubscribeInfo& subscribeInfo);
    ~ScreenChangedReceiver()
    {
    }
    void OnReceiveEvent(const EventFwk::CommonEventData& data) override;

private:
    std::weak_ptr<NfcService> nfcService_ {};
    std::weak_ptr<NfcEventHandler> eventHandler_ {};
};

NfcEventHandler::ScreenChangedReceiver::ScreenChangedReceiver(std::weak_ptr<NfcService> nfcService,
    const EventFwk::CommonEventSubscribeInfo& subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo),
    nfcService_(nfcService),
    eventHandler_(nfcService.lock()->eventHandler_)
{
}

bool NfcEventHandler::IsScreenOn()
{
    return PowerMgr::PowerMgrClient::GetInstance().IsScreenOn();
}

bool NfcEventHandler::IsScreenLocked()
{
    return OHOS::ScreenLock::ScreenLockManager::GetInstance()->IsScreenLocked();
}

ScreenState NfcEventHandler::CheckScreenState()
{
    bool isScreenOn = IsScreenOn();
    bool isScreenLocked = IsScreenLocked();
    if (isScreenOn && isScreenLocked) {
        return ScreenState::SCREEN_STATE_ON_LOCKED;
    } else if (!isScreenOn && !isScreenLocked) {
        return ScreenState::SCREEN_STATE_OFF_UNLOCKED;
    } else if (!isScreenOn && isScreenLocked) {
        return ScreenState::SCREEN_STATE_OFF_LOCKED;
    } else if (isScreenOn && !isScreenLocked) {
        return ScreenState::SCREEN_STATE_ON_UNLOCKED;
    }
    return ScreenState::SCREEN_STATE_UNKNOWN;
}

void NfcEventHandler::ScreenChangedReceiver::OnReceiveEvent(const EventFwk::CommonEventData& data)
{
    std::string action = data.GetWant().GetAction();
    if (action.empty()) {
        ErrorLog("action is empty");
        return;
    }
    InfoLog("OnScreenChanged: action: %{public}s", action.c_str());
    if (eventHandler_.expired() || nfcService_.expired()) {
        ErrorLog("eventHandler_ is null.");
        return;
    }
    ScreenState screenState = ScreenState::SCREEN_STATE_UNKNOWN;
    if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON) == 0) {
        screenState = eventHandler_.lock()->IsScreenLocked() ?
            ScreenState::SCREEN_STATE_ON_LOCKED : ScreenState::SCREEN_STATE_ON_UNLOCKED;
    } else if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) == 0) {
        screenState = eventHandler_.lock()->IsScreenLocked() ?
            ScreenState::SCREEN_STATE_OFF_LOCKED : ScreenState::SCREEN_STATE_OFF_UNLOCKED;
    } else if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED) == 0) {
        nfcService_.lock()->ExecuteTask(KITS::TASK_INITIALIZE);
        screenState = eventHandler_.lock()->IsScreenOn() ?
            ScreenState::SCREEN_STATE_ON_UNLOCKED : ScreenState::SCREEN_STATE_OFF_UNLOCKED;
#ifdef NFC_HANDLE_SCREEN_LOCK
        TAG::NdefHarDispatch::HandleCarrierReport();
#endif
    } else {
        ErrorLog("Screen changed receiver event:unknown");
        return;
    }
    if (eventHandler_.expired()) {
        ErrorLog("eventHandler_ is null.");
        return;
    }
    eventHandler_.lock()->SendEvent(static_cast<uint32_t>(NfcCommonEvent::MSG_SCREEN_CHANGED),
        static_cast<int64_t>(screenState), static_cast<int64_t>(0));
}

class NfcEventHandler::PackageChangedReceiver : public EventFwk::CommonEventSubscriber {
public:
    explicit PackageChangedReceiver(std::weak_ptr<NfcService> nfcService,
        const EventFwk::CommonEventSubscribeInfo& subscribeInfo);
    ~PackageChangedReceiver()
    {
    }
    void OnReceiveEvent(const EventFwk::CommonEventData& data) override;

private:
    std::weak_ptr<NfcService> nfcService_ {};
    std::weak_ptr<AppExecFwk::EventHandler> eventHandler_ {};
};

NfcEventHandler::PackageChangedReceiver::PackageChangedReceiver(std::weak_ptr<NfcService> nfcService,
    const EventFwk::CommonEventSubscribeInfo& subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo),
    nfcService_(nfcService),
    eventHandler_(nfcService.lock()->eventHandler_)
{
}

void NfcEventHandler::PackageChangedReceiver::OnReceiveEvent(const EventFwk::CommonEventData& data)
{
    DebugLog("NfcEventHandler::PackageChangedReceiver");
    std::string action = data.GetWant().GetAction();
    if (action.empty()) {
        ErrorLog("action is empty");
        return;
    }
    if (eventHandler_.expired()) {
        ErrorLog("eventHandler_ is null.");
        return;
    }
    const std::shared_ptr<EventFwk::CommonEventData> mdata =
        std::make_shared<EventFwk::CommonEventData> (data);
    if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED) == 0 ||
        action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) == 0 ||
        action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) == 0) {
        eventHandler_.lock()->SendEvent(static_cast<uint32_t>(NfcCommonEvent::MSG_PACKAGE_UPDATED),
            mdata, static_cast<int64_t>(0));
    }
}

class NfcEventHandler::ShutdownEventReceiver : public EventFwk::CommonEventSubscriber {
public:
    explicit ShutdownEventReceiver(std::weak_ptr<NfcService> nfcService,
        const EventFwk::CommonEventSubscribeInfo& subscribeInfo);
    ~ShutdownEventReceiver()
    {
    }
    void OnReceiveEvent(const EventFwk::CommonEventData& data) override;

private:
    std::weak_ptr<NfcService> nfcService_ {};
    std::weak_ptr<AppExecFwk::EventHandler> eventHandler_ {};
};

NfcEventHandler::ShutdownEventReceiver::ShutdownEventReceiver(std::weak_ptr<NfcService> nfcService,
    const EventFwk::CommonEventSubscribeInfo& subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo),
    nfcService_(nfcService),
    eventHandler_(nfcService.lock()->eventHandler_)
{
}

void NfcEventHandler::ShutdownEventReceiver::OnReceiveEvent(const EventFwk::CommonEventData& data)
{
    DebugLog("NfcEventHandler::ShutdownEventReceiver");
    std::string action = data.GetWant().GetAction();
    if (action.empty()) {
        ErrorLog("action is empty");
        return;
    }
    if (eventHandler_.expired()) {
        ErrorLog("eventHandler_ is null.");
        return;
    }
    if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_SHUTDOWN) == 0) {
        eventHandler_.lock()->SendEvent(static_cast<uint32_t>(NfcCommonEvent::MSG_SHUTDOWN),
                                        static_cast<int64_t>(0));
    }
}

class NfcEventHandler::DataShareChangedReceiver : public EventFwk::CommonEventSubscriber {
public:
    explicit DataShareChangedReceiver(std::weak_ptr<NfcService> nfcService,
        const EventFwk::CommonEventSubscribeInfo& subscribeInfo);
    ~DataShareChangedReceiver()
    {
    }
    void OnReceiveEvent(const EventFwk::CommonEventData& data) override;

private:
    std::weak_ptr<NfcService> nfcService_ {};
    std::weak_ptr<AppExecFwk::EventHandler> eventHandler_ {};
};

NfcEventHandler::DataShareChangedReceiver::DataShareChangedReceiver(std::weak_ptr<NfcService> nfcService,
    const EventFwk::CommonEventSubscribeInfo& subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo),
    nfcService_(nfcService),
    eventHandler_(nfcService.lock()->eventHandler_)
{
}

void NfcEventHandler::DataShareChangedReceiver::OnReceiveEvent(const EventFwk::CommonEventData& data)
{
    DebugLog("NfcEventHandler::DataShareChangedReceiver");
    std::string action = data.GetWant().GetAction();
    if (action.empty()) {
        ErrorLog("action is empty");
        return;
    }
    InfoLog("DataShareChangedReceiver: action = %{public}s", action.c_str());
    if (action.compare(EVENT_DATA_SHARE_READY) == 0 && !eventHandler_.expired()) {
        eventHandler_.lock()->SendEvent(static_cast<uint32_t>(NfcCommonEvent::MSG_DATA_SHARE_READY),
                                        static_cast<int64_t>(0));
    }
}

NfcEventHandler::NfcEventHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
                                 std::weak_ptr<NfcService> service)
    : EventHandler(runner), nfcService_(service)
{
}

NfcEventHandler::~NfcEventHandler()
{
    EventFwk::CommonEventManager::UnSubscribeCommonEvent(screenSubscriber_);
    EventFwk::CommonEventManager::UnSubscribeCommonEvent(pkgSubscriber_);
    EventFwk::CommonEventManager::UnSubscribeCommonEvent(shutdownSubscriber_);
    EventFwk::CommonEventManager::UnSubscribeCommonEvent(dataShareSubscriber_);
}

void NfcEventHandler::Intialize(std::weak_ptr<TAG::TagDispatcher> tagDispatcher,
                                std::weak_ptr<CeService> ceService,
                                std::weak_ptr<NfcPollingManager> nfcPollingManager,
                                std::weak_ptr<NfcRoutingManager> nfcRoutingManager,
                                std::weak_ptr<NCI::INciNfccInterface> nciNfccProxy)
{
    DebugLog("NfcEventHandler::Intialize");
    tagDispatcher_ = tagDispatcher;
    ceService_ = ceService;
    nfcPollingManager_ = nfcPollingManager;
    nfcRoutingManager_ = nfcRoutingManager;
    nciNfccProxy_ = nciNfccProxy;

    SubscribeScreenChangedEvent();
    SubscribePackageChangedEvent();
    SubscribeShutdownEvent();
    SubscribeDataShareChangedEvent();
}

void NfcEventHandler::SubscribeScreenChangedEvent()
{
    std::lock_guard<std::mutex> guard(commonEventMutex_);
    if (screenSubscriber_ != nullptr) {
        InfoLog("Screen changed event is subscribed, skip");
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    screenSubscriber_ = std::make_shared<ScreenChangedReceiver>(nfcService_, subscribeInfo);
    if (screenSubscriber_ == nullptr) {
        ErrorLog("Create screen changed subscriber failed");
        return;
    }

    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(screenSubscriber_)) {
        ErrorLog("Subscribe screen changed event fail");
    }
}

void NfcEventHandler::SubscribePackageChangedEvent()
{
    std::lock_guard<std::mutex> guard(commonEventMutex_);
    if (pkgSubscriber_ != nullptr) {
        InfoLog("Package changed subscriber is subscribed, skip");
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    pkgSubscriber_ = std::make_shared<PackageChangedReceiver>(nfcService_, subscribeInfo);
    if (pkgSubscriber_ == nullptr) {
        ErrorLog("Create package changed subscriber failed");
        return;
    }

    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(pkgSubscriber_)) {
        ErrorLog("Subscribe package changed event fail");
    }
}

void NfcEventHandler::SubscribeShutdownEvent()
{
    std::lock_guard<std::mutex> guard(commonEventMutex_);
    if (shutdownSubscriber_ != nullptr) {
        InfoLog("Shutdown event is subscribed, skip");
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SHUTDOWN);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    shutdownSubscriber_ = std::make_shared<ShutdownEventReceiver>(nfcService_, subscribeInfo);
    if (shutdownSubscriber_ == nullptr) {
        ErrorLog("Create shutdown subscriber failed");
        return;
    }

    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(shutdownSubscriber_)) {
        ErrorLog("Subscribe shutdown event fail");
    }
}

void NfcEventHandler::SubscribeDataShareChangedEvent()
{
    std::lock_guard<std::mutex> guard(commonEventMutex_);
    if (dataShareSubscriber_ != nullptr) {
        InfoLog("DataShare changed event is subscribed, skip");
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT_DATA_SHARE_READY);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    dataShareSubscriber_ = std::make_shared<DataShareChangedReceiver>(nfcService_, subscribeInfo);
    if (dataShareSubscriber_ == nullptr) {
        ErrorLog("dataShareSubscriber_ failed");
        return;
    }

    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(dataShareSubscriber_)) {
        ErrorLog("Subscribe dataShareSubscriber_ fail");
    }
}

void NfcEventHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer& event)
{
    if (event == nullptr) {
        ErrorLog("event is nullptr");
        return;
    }
    NfcCommonEvent eventId = static_cast<NfcCommonEvent>(event->GetInnerEventId());
    if (eventId != NfcCommonEvent::MSG_NOTIFY_FIELD_OFF &&
        eventId != NfcCommonEvent::MSG_NOTIFY_FIELD_ON) {
        InfoLog("NFC common event handler receive a message of %{public}d", eventId);
    }
    NfcWatchDog nfcProcessEventDog(
        "ProcessEvent_" + std::to_string(static_cast<int>(eventId)), WAIT_PROCESS_EVENT_TIMES, nciNfccProxy_);
    nfcProcessEventDog.Run();
    switch (eventId) {
        case NfcCommonEvent::MSG_TAG_FOUND:
            if (!tagDispatcher_.expired()) {
                tagDispatcher_.lock()->HandleTagFound(event->GetParam());
            }
            break;
        case NfcCommonEvent::MSG_TAG_DEBOUNCE:
            if (!tagDispatcher_.expired()) {
                tagDispatcher_.lock()->HandleTagDebounce();
            }
            break;
        case NfcCommonEvent::MSG_TAG_LOST:
            if (!tagDispatcher_.expired()) {
                tagDispatcher_.lock()->HandleTagLost(event->GetParam());
            }
            break;
        case NfcCommonEvent::MSG_SCREEN_CHANGED: {
            if (!nfcPollingManager_.expired()) {
                nfcPollingManager_.lock()->HandleScreenChanged(event->GetParam());
            }
            break;
        }
        case NfcCommonEvent::MSG_PACKAGE_UPDATED: {
            if (nfcPollingManager_.expired()) {
                break;
            }
            bool updated = nfcPollingManager_.lock()->HandlePackageUpdated(
                event->GetSharedObject<EventFwk::CommonEventData>());
            if (updated) {
                ceService_.lock()->OnAppAddOrChangeOrRemove(event->GetSharedObject<EventFwk::CommonEventData>());
            }
            break;
        }
        case NfcCommonEvent::MSG_COMMIT_ROUTING: {
            if (!nfcRoutingManager_.expired()) {
                nfcRoutingManager_.lock()->HandleCommitRouting();
            }
            break;
        }
        case NfcCommonEvent::MSG_COMPUTE_ROUTING_PARAMS: {
            int defaultPaymentType = event->GetParam();
            if (!nfcRoutingManager_.expired()) {
                nfcRoutingManager_.lock()->HandleComputeRoutingParams(defaultPaymentType);
            }
            break;
        }
        case NfcCommonEvent::MSG_FIELD_ACTIVATED: {
            if (!ceService_.expired()) {
                ceService_.lock()->HandleFieldActivated();
            }
            break;
        }
        case NfcCommonEvent::MSG_FIELD_DEACTIVATED: {
            if (!ceService_.expired()) {
                ceService_.lock()->HandleFieldDeactivated();
            }
            break;
        }
        case NfcCommonEvent::MSG_NOTIFY_FIELD_ON: {
            if (!ceService_.expired()) {
                ceService_.lock()->PublishFieldOnOrOffCommonEvent(true);
            }
            break;
        }
        case NfcCommonEvent::MSG_NOTIFY_FIELD_OFF: {
            if (!ceService_.expired()) {
                ceService_.lock()->PublishFieldOnOrOffCommonEvent(false);
            }
            break;
        }
        case NfcCommonEvent::MSG_NOTIFY_FIELD_OFF_TIMEOUT: {
            if (!ceService_.expired()) {
                ceService_.lock()->PublishFieldOnOrOffCommonEvent(false);
            }
            break;
        }
        case NfcCommonEvent::MSG_SHUTDOWN: {
            if (!nfcService_.expired()) {
                nfcService_.lock()->HandleShutdown();
            }
            break;
        }
        case NfcCommonEvent::MSG_DATA_SHARE_READY: {
            if (!ceService_.expired()) {
                ceService_.lock()->HandleDataShareReady();
            }
            break;
        }
#ifdef VENDOR_APPLICATIONS_ENABLED
        case NfcCommonEvent::MSG_VENDOR_EVENT: {
            int eventType = event->GetParam();
            if ((eventType == KITS::VENDOR_APP_INIT_DONE || eventType == KITS::VENDOR_APP_CHANGE)
                && !ceService_.expired()) {
                ceService_.lock()->ConfigRoutingAndCommit();
            }
            break;
        }
#endif
#ifdef NDEF_WIFI_ENABLED
        case NfcCommonEvent::MSG_WIFI_ENABLE_TIMEOUT: {
            TAG::WifiConnectionManager::GetInstance().HandleWifiEnableFailed();
            break;
        }
        case NfcCommonEvent::MSG_WIFI_CONNECT_TIMEOUT: {
            TAG::WifiConnectionManager::GetInstance().HandleWifiConnectFailed();
            break;
        }
        case NfcCommonEvent::MSG_WIFI_ENABLED: {
            TAG::WifiConnectionManager::GetInstance().OnWifiEnabled();
            break;
        }
        case NfcCommonEvent::MSG_WIFI_CONNECTED: {
            TAG::WifiConnectionManager::GetInstance().OnWifiConnected();
            break;
        }
        case NfcCommonEvent::MSG_WIFI_NTF_CLICKED: {
            TAG::WifiConnectionManager::GetInstance().OnWifiNtfClicked();
            break;
        }
#endif
#ifdef NDEF_BT_ENABLED
        case NfcCommonEvent::MSG_BT_ENABLE_TIMEOUT: {
            TAG::BtConnectionManager::GetInstance().HandleBtEnableFailed();
            break;
        }
        case NfcCommonEvent::MSG_BT_PAIR_TIMEOUT: {
            TAG::BtConnectionManager::GetInstance().HandleBtPairFailed();
            break;
        }
        case NfcCommonEvent::MSG_BT_CONNECT_TIMEOUT: {
            TAG::BtConnectionManager::GetInstance().HandleBtConnectFailed();
            break;
        }
        case NfcCommonEvent::MSG_BT_ENABLED: {
            TAG::BtConnectionManager::GetInstance().OnBtEnabled();
            break;
        }
        case NfcCommonEvent::MSG_BT_PAIR_STATUS_CHANGED: {
            TAG::BtConnectionManager::GetInstance().OnPairStatusChanged(
                event->GetSharedObject<TAG::BtConnectionInfo>());
            break;
        }
        case NfcCommonEvent::MSG_BT_CONNECT_STATUS_CHANGED: {
            TAG::BtConnectionManager::GetInstance().OnConnectionStateChanged(
                event->GetSharedObject<TAG::BtConnectionInfo>());
            break;
        }
        case NfcCommonEvent::MSG_BT_NTF_CLICKED: {
            TAG::BtConnectionManager::GetInstance().OnBtNtfClicked();
            break;
        }
#endif
        default:
            ErrorLog("Unknown message received: id %{public}d", eventId);
            break;
    }
    nfcProcessEventDog.Cancel();
}
}  // namespace NFC
}  // namespace OHOS
