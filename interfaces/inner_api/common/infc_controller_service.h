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
#ifndef I_NFC_CONTROLLER_SERVICE_H
#define I_NFC_CONTROLLER_SERVICE_H

#include "nfc_sdk_common.h"
#include "indef_msg_callback.h"
#include "infc_controller_callback.h"
#ifdef VENDOR_APPLICATIONS_ENABLED
#include "ion_card_emulation_notify_cb.h"
#include "iquery_app_info_callback.h"
#endif
#include "iremote_broker.h"
#include "element_name.h"

namespace OHOS {
namespace NFC {
class INfcControllerService : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.nfc.INfcControllerService");

    virtual ~INfcControllerService() {}
    /**
     * @brief  Get the NFC state
     * @return The NFC State
     */
    virtual int GetState() = 0;
    /**
     * @brief Turn On NFC
     * @return The status code of calling function.
     */
    virtual int TurnOn() = 0;
    /**
     * @brief Turn Off NFC
     * @return The status code of calling function.
     */
    virtual int TurnOff() = 0;
     /**
     * @brief NFC enable
     * @param isOpen The output for checking nfc is open or not.
     * @return The status code of calling function.
     */
    virtual int IsNfcOpen(bool &isOpen) = 0;

    virtual KITS::ErrorCode RegisterCallBack(const sptr<INfcControllerCallback> &callback,
        const std::string& type) = 0;
    virtual KITS::ErrorCode UnRegisterCallBack(const std::string& type) = 0;
    virtual OHOS::sptr<IRemoteObject> GetTagServiceIface() = 0;
    virtual OHOS::sptr<IRemoteObject> GetHceServiceIface(int32_t &res) = 0;
    virtual KITS::ErrorCode RegNdefMsgCb(const sptr<INdefMsgCallback> &callback) = 0;
#ifdef VENDOR_APPLICATIONS_ENABLED
    virtual KITS::ErrorCode RegQueryApplicationCb(sptr<IQueryAppInfoCallback> callback) = 0;
    virtual KITS::ErrorCode RegCardEmulationNotifyCb(sptr<IOnCardEmulationNotifyCb> callback) = 0;
    virtual KITS::ErrorCode NotifyEventStatus(int eventType, int arg1, std::string arg2) = 0;
#endif
};
}  // namespace NFC
}  // namespace OHOS
#endif  // I_NFC_CONTROLLER_SERVICE_H
