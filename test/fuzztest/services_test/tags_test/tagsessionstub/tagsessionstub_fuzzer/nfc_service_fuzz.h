/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef NFCSERVICE_FUZZER_H
#define NFCSERVICE_FUZZER_H

#include "infc_service.h"

namespace OHOS {
namespace NFC {
class NfcServiceFuzz final : public INfcService {
private:
    std::weak_ptr<TAG::TagDispatcher> GetTagDispatcher() override;

    bool IsNfcEnabled() override;
    int GetNfcState() override;
    int GetScreenState() override;
    int GetNciVersion() override;
    std::weak_ptr<NCI::INfccHost> GetNfccHost() override
    {
        return nfccHost_;
    }
private:
    // NCI
    std::shared_ptr<NCI::INfccHost> nfccHost_ {};

public:
    NfcServiceFuzz() {};
    virtual ~NfcServiceFuzz() {};
    OHOS::sptr<IRemoteObject> GetTagServiceIface() override;
    bool EnableForegroundDispatch(AppExecFwk::ElementName element, std::vector<uint32_t> &discTech,
        const sptr<KITS::IForegroundCallback> &callback) override;
    bool DisableForegroundDispatch(AppExecFwk::ElementName element) override;
    bool DisableForegroundByDeathRcpt() override;
    bool IsForegroundEnabled() override;
    void SendTagToForeground(KITS::TagInfoParcelable tagInfo) override;
};
}
}
#endif