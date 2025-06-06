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
#include "nfc_routing_manager.h"

#include "loghelper.h"
#include "nfc_service.h"
#include "nfc_watch_dog.h"

namespace OHOS {
namespace NFC {
// ms wait for setting the routing table.
const int ROUTING_DELAY_TIME = 0; // ms
NfcRoutingManager::NfcRoutingManager(std::shared_ptr<NfcEventHandler> eventHandler,
                                     std::weak_ptr<NCI::INciNfccInterface> nciNfccProxy,
                                     std::weak_ptr<NCI::INciCeInterface> nciCeProxy,
                                     std::weak_ptr<NfcService> nfcService)
    : eventHandler_(eventHandler), nciNfccProxy_(nciNfccProxy), nciCeProxy_(nciCeProxy), nfcService_(nfcService)
{}

NfcRoutingManager::~NfcRoutingManager()
{
    eventHandler_ = nullptr;
}

void NfcRoutingManager::CommitRouting()
{
    eventHandler_->SendEvent(static_cast<uint32_t>(NfcCommonEvent::MSG_COMMIT_ROUTING), ROUTING_DELAY_TIME);
}

void NfcRoutingManager::HandleCommitRouting()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (nfcService_.expired() || nciCeProxy_.expired()) {
        ErrorLog("HandleCommitRouting nfcService_ or nciCeProxy_ is nullptr.");
        return;
    }
    int nfcState = nfcService_.lock()->GetNfcState();
    if (nfcState == KITS::STATE_OFF || nfcState == KITS::STATE_TURNING_OFF) {
        WarnLog("HandleCommitRouting: NOT Handle CommitRouting in state off or turning off.");
        return;
    }
    std::shared_ptr<NfcPollingParams> currPollingParams =
        nfcService_.lock()->GetNfcPollingManager().lock()->GetCurrentParameters();
    if (currPollingParams == nullptr) {
        ErrorLog("HandleCommitRouting: currPollingParams is nullptr.");
        return;
    }
    NfcWatchDog CommitRoutingDog("CommitRouting", WAIT_ROUTING_INIT, nciNfccProxy_);
    CommitRoutingDog.Run();
    if (currPollingParams->ShouldEnablePolling()) {
        bool result = nciCeProxy_.lock()->CommitRouting();
        DebugLog("HandleCommitRouting: result = %{public}d", result);
    } else {
        ErrorLog("HandleCommitRouting: NOT Handle CommitRouting when polling not enabled.");
    }
    CommitRoutingDog.Cancel();
}

void NfcRoutingManager::ComputeRoutingParams(KITS::DefaultPaymentType defaultPaymentType)
{
    eventHandler_->SendEvent(static_cast<uint32_t>(NfcCommonEvent::MSG_COMPUTE_ROUTING_PARAMS),
                             static_cast<int>(defaultPaymentType), ROUTING_DELAY_TIME);
}

void NfcRoutingManager::HandleComputeRoutingParams(int defaultPaymentType)
{
    if (nfcService_.expired() || nciCeProxy_.expired()) {
        ErrorLog("HandleComputeRoutingParams nfcService_ or nciCeProxy_ is nullptr.");
        return;
    }
    if (!nfcService_.lock()->IsNfcEnabled()) {
        ErrorLog("HandleComputeRoutingParams: NFC not enabled, do not Compute Routing Params");
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    NfcWatchDog ComputeRoutingParamDog("ComputeRoutingParam", WAIT_ROUTING_INIT, nciNfccProxy_);
    ComputeRoutingParamDog.Run();
    bool result = nciCeProxy_.lock()->ComputeRoutingParams(defaultPaymentType);
    DebugLog("HandleComputeRoutingParams result = %{public}d", result);
    ComputeRoutingParamDog.Cancel();
}
} // namespace NFC
} // namespace OHOS