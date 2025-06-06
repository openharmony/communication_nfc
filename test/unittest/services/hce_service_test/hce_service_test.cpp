/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <thread>

#include "hce_service.h"
#include "nfc_controller.h"
#include "hce_cmd_callback_stub.h"

namespace OHOS {
namespace NFC {
namespace TEST {
using namespace testing::ext;
using namespace OHOS::NFC::KITS;
using namespace OHOS::NFC::HCE;
class HceServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HceServiceTest::SetUpTestCase()
{
    std::cout << " SetUpTestCase HceServiceTest." << std::endl;
}

void HceServiceTest::TearDownTestCase()
{
    std::cout << " TearDownTestCase HceServiceTest." << std::endl;
}

void HceServiceTest::SetUp()
{
    std::cout << " SetUp HceServiceTest." << std::endl;
}

void HceServiceTest::TearDown()
{
    std::cout << " TearDown HceServiceTest." << std::endl;
}

class HceCmdListener : public IHceCmdCallback {
public:
    HceCmdListener() {}

    virtual ~HceCmdListener() {}

public:
    void OnCeApduData(const std::vector<uint8_t>& data) override
    {
        std::cout << "OnCeApduData" << std::endl;
    }

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

/**
 * @tc.name: RegHceCmdCallback001
 * @tc.desc: Test HceServiceTest RegHceCmdCallback.
 * @tc.type: FUNC
 */
HWTEST_F(HceServiceTest, RegHceCmdCallback001, TestSize.Level1)
{
    sptr<HceCmdListener> callback = sptr<HceCmdListener>(new (std::nothrow) HceCmdListener());
    HceService::GetInstance().RegHceCmdCallback(callback, "hceCmd");
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int ret = HceCmdCallbackStub::GetInstance().OnRemoteRequest(code, data, reply, option);
    ASSERT_TRUE(ret == KITS::ERR_NFC_PARAMETERS);
}

/**
 * @tc.name: UnRegHceCmdCallback001
 * @tc.desc: Test HceServiceTest UnRegHceCmdCallback.
 * @tc.type: FUNC
 */
HWTEST_F(HceServiceTest, UnRegHceCmdCallback001, TestSize.Level1)
{
    sptr<HceCmdListener> callback = sptr<HceCmdListener>(new (std::nothrow) HceCmdListener());
    HceService::GetInstance().UnRegHceCmdCallback(callback, "hceCmd");
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int ret = HceCmdCallbackStub::GetInstance().OnRemoteRequest(code, data, reply, option);
    ASSERT_TRUE(ret == KITS::ERR_NFC_PARAMETERS);
}

/**
 * @tc.name: SendRawFrame001
 * @tc.desc: Test HceServiceTest SendRawFrame001.
 * @tc.type: FUNC
 */
HWTEST_F(HceServiceTest, SendRawFrame001, TestSize.Level1)
{
    std::string hexCmdData = "010203";
    std::string hexRespData = "";
    HceService::GetInstance().SendRawFrame(hexCmdData, true, hexRespData);
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int ret = HceCmdCallbackStub::GetInstance().OnRemoteRequest(code, data, reply, option);
    ASSERT_TRUE(ret == KITS::ERR_NFC_PARAMETERS);
}

/**
 * @tc.name: GetPaymentServices001
 * @tc.desc: Test HceServiceTest GetPaymentServices001.
 * @tc.type: FUNC
 */
HWTEST_F(HceServiceTest, GetPaymentServices001, TestSize.Level1)
{
    std::vector<AbilityInfo> abilityInfos;
    HceService::GetInstance().GetPaymentServices(abilityInfos);
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int ret = HceCmdCallbackStub::GetInstance().OnRemoteRequest(code, data, reply, option);
    ASSERT_TRUE(ret == KITS::ERR_NFC_PARAMETERS);
}

/**
 * @tc.name: IsDefaultService001
 * @tc.desc: Test HceServiceTest IsDefaultService001.
 * @tc.type: FUNC
 */
HWTEST_F(HceServiceTest, IsDefaultService001, TestSize.Level1)
{
    ElementName element;
    const std::string type = "";
    bool isDefaultService = true;
    HceService::GetInstance().IsDefaultService(element, type, isDefaultService);
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int ret = HceCmdCallbackStub::GetInstance().OnRemoteRequest(code, data, reply, option);
    ASSERT_TRUE(ret == KITS::ERR_NFC_PARAMETERS);
}

/**
 * @tc.name: StopHce001
 * @tc.desc: Test HceServiceTest StopHce001.
 * @tc.type: FUNC
 */
HWTEST_F(HceServiceTest, StopHce001, TestSize.Level1)
{
    ElementName element;
    HceService::GetInstance().StopHce(element);
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int ret = HceCmdCallbackStub::GetInstance().OnRemoteRequest(code, data, reply, option);
    ASSERT_TRUE(ret == KITS::ERR_NFC_PARAMETERS);
}

/**
 * @tc.name: RegHceCmdCallback0001
 * @tc.desc: Test HceServiceTest RegHceCmdCallback.
 * @tc.type: FUNC
 */
HWTEST_F(HceServiceTest, RegHceCmdCallback0001, TestSize.Level1)
{
    sptr<HceCmdListener> callback = nullptr;
    KITS::ErrorCode ret = HceCmdCallbackStub::GetInstance().RegHceCmdCallback(callback);
    ASSERT_TRUE(ret == NFC::KITS::ErrorCode::ERR_NFC_PARAMETERS);
}

/**
 * @tc.name: RegHceCmdCallback0002
 * @tc.desc: Test HceServiceTest RegHceCmdCallback.
 * @tc.type: FUNC
 */
HWTEST_F(HceServiceTest, RegHceCmdCallback0002, TestSize.Level1)
{
    sptr<HceCmdListener> callback = sptr<HceCmdListener>(new (std::nothrow) HceCmdListener());
    KITS::ErrorCode ret = HceCmdCallbackStub::GetInstance().RegHceCmdCallback(callback);
    ASSERT_TRUE(ret == NFC::KITS::ErrorCode::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest0001
 * @tc.desc: Test HceServiceTest OnRemoteRequest.
 * @tc.type: FUNC
 */
HWTEST_F(HceServiceTest, OnRemoteRequest0001, TestSize.Level1)
{
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int ret = HceCmdCallbackStub::GetInstance().OnRemoteRequest(code, data, reply, option);
    ASSERT_TRUE(ret == KITS::ERR_NFC_PARAMETERS);
}

/**
 * @tc.name: OnRemoteRequest0002
 * @tc.desc: Test HceServiceTest OnRemoteRequest.
 * @tc.type: FUNC
 */
HWTEST_F(HceServiceTest, OnRemoteRequest0002, TestSize.Level1)
{
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::u16string descriptor = u"ohos.nfc.kits.IHceCmdCallback";
    data.WriteInterfaceToken(descriptor);
    data.WriteInt32(1);
    int ret = HceCmdCallbackStub::GetInstance().OnRemoteRequest(code, data, reply, option);
    ASSERT_TRUE(ret == 1);
}

/**
 * @tc.name: OnRemoteRequest0003
 * @tc.desc: Test HceServiceTest OnRemoteRequest.
 * @tc.type: FUNC
 */
HWTEST_F(HceServiceTest, OnRemoteRequest0003, TestSize.Level1)
{
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::u16string descriptor = u"ohos.nfc.kits.IHceCmdCallback";
    data.WriteInterfaceToken(descriptor);
    data.WriteInt32(0);
    int ret = HceCmdCallbackStub::GetInstance().OnRemoteRequest(code, data, reply, option);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: OnRemoteRequest0004
 * @tc.desc: Test HceServiceTest OnRemoteRequest.
 * @tc.type: FUNC
 */
HWTEST_F(HceServiceTest, OnRemoteRequest0004, TestSize.Level1)
{
    uint32_t code = 304;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::u16string descriptor = u"ohos.nfc.kits.IHceCmdCallback";
    data.WriteInterfaceToken(descriptor);
    data.WriteInt32(0);
    int ret = HceCmdCallbackStub::GetInstance().OnRemoteRequest(code, data, reply, option);
    ASSERT_TRUE(ret == KITS::ERR_NONE);
}
}
}
}