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
#include "nfc_controller_impl.h"
#include "nfc_sdk_common.h"
#include "nfc_service.h"
#include "loghelper.h"
#include "external_deps_proxy.h"
#include "parameter.h"

namespace OHOS {
namespace NFC {
const std::string DUMP_LINE = "---------------------------";
const std::string DUMP_END = "\n";

NfcControllerImpl::NfcControllerImpl(std::weak_ptr<NfcService> nfcService)
    : NfcControllerStub(), nfcService_(nfcService)
{
}

NfcControllerImpl::~NfcControllerImpl()
{
}

int NfcControllerImpl::GetState()
{
    if (nfcService_.expired()) {
        return KITS::ERR_NFC_PARAMETERS;
    }
    return nfcService_.lock()->GetNfcState();
}

inline bool IsNfcEdmDisallowed()
{
    const char* nfcEdmKey = "persist.edm.nfc_disable";
    const uint32_t paramTrueLen = 4; // "true" 4 bytes
    const uint32_t paramFalseLen = 5; // "false" 5 bytes
    char result[paramFalseLen + 1] = {0};
    // Returns the number of bytes of the system parameter if the operation is successful.
    int len = GetParameter(nfcEdmKey, "false", result, paramFalseLen + 1);
    if (len != paramFalseLen && len != paramTrueLen) {
        ErrorLog("GetParameter edm len is invalid.");
        return false;
    }
    if (strncmp(result, "true", paramTrueLen) == 0) {
        WarnLog("nfc is prohibited by EDM. You won't be able to turn on nfc!");
        return true;
    }
    return false;
}

int NfcControllerImpl::TurnOn()
{
    if (IsNfcEdmDisallowed()) {
        ErrorLog("nfc edm disallowed");
        return KITS::ERR_NFC_EDM_DISALLOWED;
    }
    if (nfcService_.expired()) {
        return KITS::ERR_NFC_PARAMETERS;
    }
    return nfcService_.lock()->ExecuteTask(KITS::TASK_TURN_ON);
}

int NfcControllerImpl::TurnOff()
{
    if (nfcService_.expired()) {
        return KITS::ERR_NFC_PARAMETERS;
    }
    return nfcService_.lock()->ExecuteTask(KITS::TASK_TURN_OFF);
}

int NfcControllerImpl::IsNfcOpen(bool &isOpen)
{
    if (nfcService_.expired()) {
        return KITS::ERR_NFC_PARAMETERS;
    }
    isOpen = nfcService_.lock()->IsNfcEnabled();
    return KITS::ERR_NONE;
}

KITS::ErrorCode NfcControllerImpl::RegisterCallBack(const sptr<INfcControllerCallback> &callback,
    const std::string& type, Security::AccessToken::AccessTokenID callerToken)
{
    if (nfcService_.expired()) {
        return KITS::ERR_NFC_PARAMETERS;
    }
    if (!nfcService_.lock()->SetRegisterCallBack(callback, type, callerToken)) {
        return KITS::ERR_NONE;
    }
    return KITS::ERR_NFC_PARAMETERS;
}

KITS::ErrorCode NfcControllerImpl::UnRegisterCallBack(const std::string& type,
    Security::AccessToken::AccessTokenID callerToken)
{
    if (nfcService_.expired()) {
        return KITS::ERR_NFC_PARAMETERS;
    }
    if (!nfcService_.lock()->RemoveRegisterCallBack(type, callerToken)) {
        return KITS::ERR_NONE;
    }
    return KITS::ERR_NFC_PARAMETERS;
}

KITS::ErrorCode NfcControllerImpl::UnRegisterAllCallBack(Security::AccessToken::AccessTokenID callerToken)
{
    if (nfcService_.expired()) {
        return KITS::ERR_NFC_PARAMETERS;
    }
    if (!nfcService_.lock()->RemoveAllRegisterCallBack(callerToken)) {
        return KITS::ERR_NONE;
    }
    return KITS::ERR_NFC_PARAMETERS;
}

OHOS::sptr<IRemoteObject> NfcControllerImpl::GetTagServiceIface()
{
    if (nfcService_.expired()) {
        return nullptr;
    }
    return nfcService_.lock()->GetTagServiceIface();
}

KITS::ErrorCode NfcControllerImpl::RegNdefMsgCallback(const sptr<INdefMsgCallback> &callback)
{
    if (nfcService_.expired()) {
        ErrorLog("NfcControllerImpl::RegNdefMsgCallback nfcService_ expired");
        return KITS::ERR_NFC_PARAMETERS;
    }
    if (nfcService_.lock()->RegNdefMsgCb(callback)) {
        return KITS::ERR_NONE;
    }
    return KITS::ERR_NFC_PARAMETERS;
}

#ifdef VENDOR_APPLICATIONS_ENABLED
KITS::ErrorCode NfcControllerImpl::RegQueryApplicationCb(const sptr<IQueryAppInfoCallback> callback)
{
    ExternalDepsProxy::GetInstance().RegQueryApplicationCb(callback);
    return KITS::ERR_NONE;
}

KITS::ErrorCode NfcControllerImpl::RegCardEmulationNotifyCb(const sptr<IOnCardEmulationNotifyCb> callback)
{
    ExternalDepsProxy::GetInstance().RegCardEmulationNotifyCb(callback);
    return KITS::ERR_NONE;
}
KITS::ErrorCode NfcControllerImpl::NotifyEventStatus(int eventType, int arg1, std::string arg2)
{
    if (nfcService_.expired()) {
        return KITS::ERR_NFC_PARAMETERS;
    }

    nfcService_.lock()->OnVendorEvent(eventType, arg1, arg2);
    return KITS::ErrorCode();
}
#endif

OHOS::sptr<IRemoteObject> NfcControllerImpl::GetHceServiceIface(int32_t &res)
{
    if (nfcService_.expired()) {
        return nullptr;
    }
    return nfcService_.lock()->GetHceServiceIface();
}

int32_t NfcControllerImpl::Dump(int32_t fd, const std::vector<std::u16string>& args)
{
    if (nfcService_.expired()) {
        return KITS::ERR_NFC_PARAMETERS;
    }
    std::string info = GetDumpInfo();
    int ret = dprintf(fd, "%s\n", info.c_str());
    if (ret < 0) {
        ErrorLog("NfcControllerImpl Dump ret = %{public}d", ret);
        return KITS::ERR_NFC_PARAMETERS;
    }
    return KITS::ERR_NONE;
}

std::string NfcControllerImpl::GetDumpInfo()
{
    std::string info;
    return info.append(DUMP_LINE)
        .append(" NFC DUMP ")
        .append(DUMP_LINE)
        .append(DUMP_END)
        .append("NFC_STATE          : ")
        .append(std::to_string(nfcService_.lock()->GetNfcState()))
        .append(DUMP_END)
        .append("SCREEN_STATE       : ")
        .append(std::to_string(nfcService_.lock()->GetScreenState()))
        .append(DUMP_END)
        .append("NCI_VERSION        : ")
        .append(std::to_string(nfcService_.lock()->GetNciVersion()))
        .append(DUMP_END);
}
}  // namespace NFC
}  // namespace OHOS
