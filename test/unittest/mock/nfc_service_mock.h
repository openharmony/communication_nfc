/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef MOCK_NFC_SERVICE_H
#define MOCK_NFC_SERVICE_H
#include <future>
#include <mutex>
#include "nfc_service.h"

namespace OHOS {
namespace NFC {
class MockNfcService : public NfcService {
public:
    bool Initialize();
    std::weak_ptr<NfcService> GetInstance() const;
    void OnTagDiscovered(uint32_t tagDiscId) override;
    void OnTagLost(uint32_t tagDiscId) override;
    void FieldActivated() override;
    void FieldDeactivated() override;
#ifdef VENDOR_APPLICATIONS_ENABLED
    void OnVendorEvent(int eventType, int arg1, std::string arg2);
#endif
    void OnCardEmulationData(const std::vector<uint8_t>& data) override;
    void OnCardEmulationActivated() override;
    void OnCardEmulationDeactivated() override;
    OHOS::sptr<IRemoteObject> GetTagServiceIface() override;
    OHOS::sptr<IRemoteObject> GetHceServiceIface() override;

    bool IsNfcEnabled() override;
    int GetNfcState() override;
    int GetScreenState() override;
    int GetNciVersion() override;
    std::weak_ptr<NCI::INciNfccInterface> GetNciNfccProxy(void);
    std::weak_ptr<NCI::INciTagInterface> GetNciTagProxy(void);
    std::weak_ptr<NfcPollingManager> GetNfcPollingManager() override;
    std::weak_ptr<NfcRoutingManager> GetNfcRoutingManager() override;

    std::weak_ptr<CeService> GetCeService() override;
    std::string GetSimVendorBundleName() override;

    std::weak_ptr<TAG::TagDispatcher> GetTagDispatcher() override;
    void NotifyMessageToVendor(int key, const std::string &value);

private:
    std::weak_ptr<NfcService> nfcService_ {};
    std::shared_ptr<NCI::INciNfccInterface> nciNfccProxy_ {};
    std::shared_ptr<NCI::INciTagInterface> nciTagProxy_ {};
    std::shared_ptr<NCI::INciCeInterface> nciCeProxy_ {};
    // polling manager
    std::shared_ptr<NfcPollingManager> nfcPollingManager_ {};
    // routing manager
    std::shared_ptr<NfcRoutingManager> nfcRoutingManager_ {};
    OHOS::sptr<IRemoteObject> tagSessionIface_{};
    OHOS::sptr<IRemoteObject> hceSessionIface_ {};
    std::shared_ptr<NfcEventHandler> eventHandler_ {};
    std::shared_ptr<CeService> ceService_ {};
    std::shared_ptr<TAG::TagDispatcher> tagDispatcher_ {};
    OHOS::sptr<NfcControllerImpl> nfcControllerImpl_ {};
};
}  // namespace NFC
}  // namespace OHOS
#endif  // MOCK_NFC_SERVICE_H
