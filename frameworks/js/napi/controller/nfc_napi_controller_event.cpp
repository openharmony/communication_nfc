/*
* Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include "nfc_napi_controller_event.h"
#include <uv.h>
#include <thread>
#include "iservice_registry.h"
#include "loghelper.h"
#include "nfc_controller.h"
#include "nfc_sdk_common.h"

namespace OHOS {
namespace NFC {
namespace KITS {
const std::string EVENT_NFC_STATE_CHANGE = "nfcStateChange";

static std::set<std::string> g_supportEventList = {
    EVENT_NFC_STATE_CHANGE,
};

constexpr uint32_t INVALID_REF_COUNT = 0xFF;
constexpr uint32_t WAIT_ON_REMOTE_DIED_MS = 20;

static std::shared_mutex g_regInfoMutex;
static std::map<std::string, std::vector<RegObj>> g_eventRegisterInfo;

class NapiEvent {
public:
    napi_value CreateResult(const napi_env& env, int value);
    bool CheckIsRegister(const std::string& type);
    void EventNotify(AsyncEventData *asyncEvent);

    template<typename T>
    void CheckAndNotify(const std::string& type, const T& obj)
    {
        std::unique_lock<std::shared_mutex> guard(g_regInfoMutex);
        if (!CheckIsRegister(type)) {
            return;
        }

        std::vector<RegObj>& vecObj = g_eventRegisterInfo[type];
        for (const auto& each : vecObj) {
            auto result = [this, env = each.m_regEnv, obj] () -> napi_value {
                return CreateResult(env, obj);
            };
            AsyncEventData *asyncEvent =
                new (std::nothrow)AsyncEventData(each.m_regEnv, each.m_regHanderRef, result);
            if (asyncEvent == nullptr) {
                return;
            }
            EventNotify(asyncEvent);
        }
    }
};

static void after_work_cb(uv_work_t *work, int status)
{
    AsyncEventData *asyncData = static_cast<AsyncEventData *>(work->data);
    InfoLog("Napi event uv_queue_work, env: %{private}p, status: %{public}d", asyncData->env, status);
    
    napi_handle_scope scope = nullptr;
    uint32_t refCount = INVALID_REF_COUNT;
    napi_open_handle_scope(asyncData->env, &scope);
    napi_value handler = nullptr;
    napi_value jsEvent = nullptr;
    if (scope == nullptr) {
        ErrorLog("scope is nullptr");
        goto EXIT;
    }

    napi_get_reference_value(asyncData->env, asyncData->callbackRef, &handler);
    if (handler == nullptr) {
        ErrorLog("handler is nullptr");
        goto EXIT;
    }
    napi_value undefine;
    napi_get_undefined(asyncData->env, &undefine);
    jsEvent = asyncData->packResult();
    if (napi_call_function(asyncData->env, nullptr, handler, 1, &jsEvent, &undefine) != napi_ok) {
        DebugLog("Report event to Js failed");
    }

EXIT:
    napi_close_handle_scope(asyncData->env, scope);
    napi_reference_unref(asyncData->env, asyncData->callbackRef, &refCount);
    InfoLog("after_work_cb unref, env: %{private}p, callbackRef: %{private}p, refCount: %{public}d",
        asyncData->env, asyncData->callbackRef, refCount);
    if (refCount == 0) {
        napi_delete_reference(asyncData->env, asyncData->callbackRef);
    }
    delete asyncData;
    delete work;
    asyncData = nullptr;
    work = nullptr;
}

void NapiEvent::EventNotify(AsyncEventData *asyncEvent)
{
    DebugLog("Enter nfc event notify");
    if (asyncEvent == nullptr) {
        DebugLog("asyncEvent is null.");
        return;
    }
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(asyncEvent->env, &loop);
    if (loop == nullptr) {
        ErrorLog("loop is null");
        delete asyncEvent;
        asyncEvent = nullptr;
        return;
    }
    uv_work_t* work = new uv_work_t;
    if (work == nullptr) {
        DebugLog("uv_work_t work is null.");
        delete asyncEvent;
        asyncEvent = nullptr;
        return;
    }

    uint32_t refCount = INVALID_REF_COUNT;
    napi_reference_ref(asyncEvent->env, asyncEvent->callbackRef, &refCount);
    work->data = asyncEvent;
    uv_after_work_cb tmp_after_work_cb = after_work_cb;
    int ret = uv_queue_work(
        loop,
        work,
        [](uv_work_t* work) {},
        tmp_after_work_cb);
    if (ret != 0) {
        ErrorLog("uv_queue_work failed.");
        delete asyncEvent;
        delete work;
    }
}

napi_value NapiEvent::CreateResult(const napi_env& env, int value)
{
    napi_value result;
    napi_create_int32(env, value, &result);
    return result;
}

bool NapiEvent::CheckIsRegister(const std::string& type)
{
    return g_eventRegisterInfo.find(type) != g_eventRegisterInfo.end();
}

class NfcStateListenerEvent : public INfcControllerCallback, public NapiEvent {
public:
    NfcStateListenerEvent() {
    }

    virtual ~NfcStateListenerEvent() {
    }

public:
    void OnNfcStateChanged(int nfcState) override
    {
        InfoLog("OnNotify rcvd nfcRfState: %{public}d", nfcState);
        CheckAndNotify(EVENT_NFC_STATE_CHANGE, nfcState);
    }

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

sptr<NfcStateListenerEvent> nfcStateListenerEvent = sptr<NfcStateListenerEvent>(new NfcStateListenerEvent());

napi_value On(napi_env env, napi_callback_info cbinfo)
{
    size_t requireArgc = 2;
    size_t argc = 2;
    napi_value argv[2] = {0};
    napi_value thisVar = 0;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc >= requireArgc, "requires 2 parameter");

    napi_valuetype eventName = napi_undefined;
    napi_typeof(env, argv[0], &eventName);
    NAPI_ASSERT(env, eventName == napi_string, "type mismatch for parameter 1");

    napi_valuetype handler = napi_undefined;
    napi_typeof(env, argv[1], &handler);
    NAPI_ASSERT(env, handler == napi_function, "type mismatch for parameter 2");

    char type[64] = {0};
    size_t typeLen = 0;
    napi_get_value_string_utf8(env, argv[0], type, sizeof(type), &typeLen);
    EventRegister::GetInstance().Register(env, type, argv[1]);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}


napi_value Off(napi_env env, napi_callback_info cbinfo)
{
    size_t requireArgc = 1;
    size_t requireArgcWithCb = 2;
    size_t argc = 2;
    napi_value argv[2] = {0};
    napi_value thisVar = 0;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc >= requireArgc, "requires at least 1 parameter");

    napi_valuetype eventName = napi_undefined;
    napi_typeof(env, argv[0], &eventName);
    NAPI_ASSERT(env, eventName == napi_string, "type mismatch for parameter 1");

    if (argc >= requireArgcWithCb) {
        napi_valuetype handler = napi_undefined;
        napi_typeof(env, argv[1], &handler);
        if (handler == napi_null || handler == napi_undefined) {
            argc -= 1;
            DebugLog("argv[1] is null or undefined, handle as no argv[1] input");
        } else {
            NAPI_ASSERT(env, handler == napi_function, "type mismatch for parameter 2");
        }
    }

    char type[64] = {0};
    size_t typeLen = 0;
    napi_get_value_string_utf8(env, argv[0], type, sizeof(type), &typeLen);
    EventRegister::GetInstance().Unregister(env, type, argc >= requireArgcWithCb ? argv[1] : nullptr);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

ErrorCode EventRegister::RegisterNfcStateChangedEvents(const std::string& type)
{
    NfcController nfcCtrl = NfcController::GetInstance();
    ErrorCode ret = nfcCtrl.RegListener(nfcStateListenerEvent, type);
    if (ret != KITS::ERR_NONE) {
        ErrorLog("RegisterNfcStateChangedEvents nfcListenerEvent failed!");
        return ret;
    }
    return ret;
}

ErrorCode EventRegister::UnRegisterNfcEvents(const std::string& type)
{
    NfcController nfcCtrl = OHOS::NFC::KITS::NfcController::GetInstance();
    ErrorCode ret = nfcCtrl.UnregListener(type);
    if (ret != KITS::ERR_NONE) {
        ErrorLog("UnRegisterNfcEvents nfcListenerEvent failed!");
        return ret;
    }
    return ret;
}

EventRegister& EventRegister::GetInstance()
{
    static EventRegister inst;
    return inst;
}

bool EventRegister::IsEventSupport(const std::string& type)
{
    return g_supportEventList.find(type) != g_supportEventList.end();
}

void EventRegister::Register(const napi_env& env, const std::string& type, napi_value handler)
{
    InfoLog("Register event: %{public}s", type.c_str());
    if (!IsEventSupport(type)) {
        ErrorLog("Register type error or not support!");
        return;
    }
    std::unique_lock<std::shared_mutex> guard(g_regInfoMutex);
    RegisterNfcStateChangedEvents(type);
    napi_ref handlerRef = nullptr;
    napi_create_reference(env, handler, 1, &handlerRef);
    RegObj regObj(env, handlerRef);
    auto iter = g_eventRegisterInfo.find(type);
    if (iter == g_eventRegisterInfo.end()) {
        g_eventRegisterInfo[type] = std::vector<RegObj> {regObj};
        return;
    }
    bool hasSameObj = false;
    for (auto miter : iter->second) {
        if (env == miter.m_regEnv) {
            napi_value handlerTemp = nullptr;
            napi_get_reference_value(miter.m_regEnv, miter.m_regHanderRef, &handlerTemp);
            bool isEqual = false;
            napi_strict_equals(miter.m_regEnv, handlerTemp, handler, &isEqual);
            if (isEqual) {
                WarnLog("handler function is same");
                hasSameObj = true;
                break;
            }
        }
    }
    if (!hasSameObj) {
        iter->second.emplace_back(regObj);
    } else {
        napi_delete_reference(env, handlerRef);
    }
}

void EventRegister::DeleteRegisterObj(const napi_env& env, std::vector<RegObj>& vecRegObjs, napi_value& handler)
{
    auto iter = vecRegObjs.begin();
    for (; iter != vecRegObjs.end();) {
        if (env == iter->m_regEnv) {
            napi_value handlerTemp = nullptr;
            napi_get_reference_value(iter->m_regEnv, iter->m_regHanderRef, &handlerTemp);
            bool isEqual = false;
            if (handlerTemp == nullptr) {
                DebugLog("handlerTemp is null");
            }
            if (handler == nullptr) {
                DebugLog("handler is null");
            }
            napi_strict_equals(iter->m_regEnv, handlerTemp, handler, &isEqual);
            DebugLog("Delete register isEqual = %{public}d", isEqual);
            if (isEqual) {
                uint32_t refCount = INVALID_REF_COUNT;
                napi_reference_unref(iter->m_regEnv, iter->m_regHanderRef, &refCount);
                InfoLog("delete ref, m_regEnv: %{private}p, m_regHanderRef: %{private}p, refCount: %{public}d",
                    iter->m_regEnv, iter->m_regHanderRef, refCount);
                if (refCount == 0) {
                    napi_delete_reference(iter->m_regEnv, iter->m_regHanderRef);
                }
                DebugLog("Delete register object ref.");
                iter = vecRegObjs.erase(iter);
            } else {
                ++iter;
            }
        } else {
            DebugLog("Unregister event, env is not equal %{private}p, : %{private}p", env, iter->m_regEnv);
            ++iter;
        }
    }
}

void EventRegister::DeleteAllRegisterObj(const napi_env& env, std::vector<RegObj>& vecRegObjs)
{
    auto iter = vecRegObjs.begin();
    for (; iter != vecRegObjs.end();) {
        if (env == iter->m_regEnv) {
            uint32_t refCount = INVALID_REF_COUNT;
            napi_reference_unref(iter->m_regEnv, iter->m_regHanderRef, &refCount);
            InfoLog("delete all ref, m_regEnv: %{private}p, m_regHanderRef: %{private}p, refCount: %{public}d",
                iter->m_regEnv, iter->m_regHanderRef, refCount);
            if (refCount == 0) {
                napi_delete_reference(iter->m_regEnv, iter->m_regHanderRef);
            }
            iter = vecRegObjs.erase(iter);
        } else {
            DebugLog("Unregister all event, env is not equal %{private}p, : %{private}p", env, iter->m_regEnv);
            ++iter;
        }
    }
}

void EventRegister::Unregister(const napi_env& env, const std::string& type, napi_value handler)
{
    InfoLog("Unregister event: %{public}s", type.c_str());
    if (!IsEventSupport(type)) {
        ErrorLog("Unregister type error or not support!");
        return;
    }
    std::unique_lock<std::shared_mutex> guard(g_regInfoMutex);
    auto iter = g_eventRegisterInfo.find(type);
    if (iter == g_eventRegisterInfo.end()) {
        WarnLog("Unregister type not registered!");
        if (UnRegisterNfcEvents(type) != KITS::ERR_NONE) {
            ErrorLog("UnRegisterNfcEvents failed.");
        }
        return;
    }
    if (handler != nullptr) {
        DeleteRegisterObj(env, iter->second, handler);
    } else {
        InfoLog("All callback is unsubscribe for event: %{public}s", type.c_str());
        DeleteAllRegisterObj(env, iter->second);
    }
    if (iter->second.empty()) {
        g_eventRegisterInfo.erase(iter);
        if (UnRegisterNfcEvents(type) != KITS::ERR_NONE) {
            ErrorLog("UnRegisterNfcEvents failed.");
        }
    }
}

void NfcNapiAbilityStatusChange::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    std::unique_lock<std::shared_mutex> guard(g_regInfoMutex);
    if (g_eventRegisterInfo.find(EVENT_NFC_STATE_CHANGE) != g_eventRegisterInfo.end()) {
        InfoLog("%{public}s g_eventRegisterInfo is not null, systemAbilityId = %{public}d", __func__, systemAbilityId);
        // sleep 20ms for waitting recv OnRemoteDied msg, to reset nfc proxy.
        std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_ON_REMOTE_DIED_MS));
        EventRegister::GetInstance().RegisterNfcStateChangedEvents(EVENT_NFC_STATE_CHANGE);
    } else {
        WarnLog("%{public}s g_eventRegisterInfo is null", __func__);
    }
}

void NfcNapiAbilityStatusChange::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    InfoLog("%{public}s, systemAbilityId = %{public}d", __func__, systemAbilityId);
}

void NfcNapiAbilityStatusChange::Init(int32_t systemAbilityId)
{
    sptr<ISystemAbilityManager> samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!samgrProxy) {
        ErrorLog("samgrProxy is nullptr");
        return;
    }
    int32_t ret = samgrProxy->SubscribeSystemAbility(systemAbilityId, this);
    InfoLog("SubscribeSystemAbility, systemAbilityId = %{public}d, ret = %{public}d", systemAbilityId, ret);
}
}  // namespace KITS
}  // namespace NFC
}  // namespace OHOS
