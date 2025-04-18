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
#include <gtest/gtest.h>
#include <thread>

#include "hce_session.h"
#include "hce_session_stub.h"

namespace OHOS {
namespace NFC {
namespace TEST {
using namespace testing::ext;
using namespace OHOS::NFC::KITS;
class HceSessionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HceSessionTest::SetUpTestCase()
{
    std::cout << " SetUpTestCase HceSessionTest." << std::endl;
}

void HceSessionTest::TearDownTestCase()
{
    std::cout << " TearDownTestCase HceSessionTest." << std::endl;
}

void HceSessionTest::SetUp()
{
    std::cout << " SetUp HceSessionTest." << std::endl;
}

void HceSessionTest::TearDown()
{
    std::cout << " TearDown HceSessionTest." << std::endl;
}

/**
 * @tc.name: HceSession001
 * @tc.desc: Test HceSessionTest HceSession.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, HceSession001, TestSize.Level1)
{
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = nullptr;
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    ASSERT_TRUE(hceSession != nullptr);
}

/**
 * @tc.name: RegHceCmdCallbackByToken001
 * @tc.desc: Test HceSessionTest RegHceCmdCallbackByToken.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, RegHceCmdCallbackByToken001, TestSize.Level1)
{
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    sptr<KITS::IHceCmdCallback> callback = nullptr;
    std::string type = "";
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    Security::AccessToken::AccessTokenID callerToken = 0;
    KITS::ErrorCode regHceCmdCallback = hceSession->RegHceCmdCallbackByToken(callback, type, callerToken);
    ASSERT_TRUE(regHceCmdCallback == NFC::KITS::ErrorCode::ERR_HCE_PARAMETERS);
}

/**
 * @tc.name: RegHceCmdCallbackByToken002
 * @tc.desc: Test HceSessionTest RegHceCmdCallbackByToken.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, RegHceCmdCallbackByToken002, TestSize.Level1)
{
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    nfcService->Initialize();
    sptr<KITS::IHceCmdCallback> callback = nullptr;
    std::string type = "";
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    Security::AccessToken::AccessTokenID callerToken = 0;
    KITS::ErrorCode regHceCmdCallback = hceSession->RegHceCmdCallbackByToken(callback, type, callerToken);
    ASSERT_TRUE(regHceCmdCallback == NFC::KITS::ErrorCode::ERR_NFC_PARAMETERS);
}

/**
 * @tc.name: SendRawFrameByToken001
 * @tc.desc: Test HceSessionTest SendRawFrameByToken.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, SendRawFrameByToken001, TestSize.Level1)
{
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    std::string hexCmdData = "";
    bool raw = false;
    std::string hexRespData = "";
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    Security::AccessToken::AccessTokenID callerToken = 0;
    int sendRawFrame = hceSession->SendRawFrameByToken(hexCmdData, raw, hexRespData, callerToken);
    ASSERT_TRUE(sendRawFrame == NFC::KITS::ErrorCode::ERR_HCE_PARAMETERS);
}

/**
 * @tc.name: SendRawFrameByToken002
 * @tc.desc: Test HceSessionTest SendRawFrameByToken.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, SendRawFrameByToken002, TestSize.Level1)
{
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    nfcService->Initialize();
    std::string hexCmdData = "";
    bool raw = false;
    std::string hexRespData = "";
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    Security::AccessToken::AccessTokenID callerToken = 0;
    int sendRawFrame = hceSession->SendRawFrameByToken(hexCmdData, raw, hexRespData, callerToken);
    ASSERT_TRUE(sendRawFrame == NFC::KITS::ErrorCode::ERR_HCE_STATE_IO_FAILED);
}

/**
 * @tc.name: Dump001
 * @tc.desc: Test HceSessionTest Dump.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, Dump001, TestSize.Level1)
{
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    int32_t fd = 0;
    std::vector<std::u16string> args;
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    int dump = hceSession->Dump(fd, args);
    ASSERT_TRUE(dump == NFC::KITS::ErrorCode::ERR_HCE_PARAMETERS);
}

/**
 * @tc.name: UnRegHceCmdCallbackByToken001
 * @tc.desc: Test HceSessionTest UnRegHceCmdCallbackByToken.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, UnRegHceCmdCallbackByToken001, TestSize.Level1)
{
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    const std::string type = "";
    Security::AccessToken::AccessTokenID callerToken = 0;
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    KITS::ErrorCode errorCode = hceSession->UnRegHceCmdCallbackByToken(type, callerToken);
    ASSERT_TRUE(errorCode == NFC::KITS::ErrorCode::ERR_HCE_PARAMETERS);
}

/**
 * @tc.name: UnRegHceCmdCallbackByToken002
 * @tc.desc: Test HceSessionTest UnRegHceCmdCallbackByToken.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, UnRegHceCmdCallbackByToken002, TestSize.Level1)
{
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    nfcService->Initialize();
    const std::string type = "";
    Security::AccessToken::AccessTokenID callerToken = 0;
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    KITS::ErrorCode errorCode = hceSession->UnRegHceCmdCallbackByToken(type, callerToken);
    ASSERT_TRUE(errorCode == NFC::KITS::ErrorCode::ERR_HCE_PARAMETERS);
}

/**
 * @tc.name: UnRegAllCallback001
 * @tc.desc: Test HceSessionTest UnRegAllCallback.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, UnRegAllCallback001, TestSize.Level1)
{
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    Security::AccessToken::AccessTokenID callerToken = 0;
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    KITS::ErrorCode errorCode = hceSession->UnRegAllCallback(callerToken);
    ASSERT_TRUE(errorCode == NFC::KITS::ErrorCode::ERR_HCE_PARAMETERS);
}

/**
 * @tc.name: UnRegAllCallback002
 * @tc.desc: Test HceSessionTest UnRegAllCallback.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, UnRegAllCallback002, TestSize.Level1)
{
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    nfcService->Initialize();
    Security::AccessToken::AccessTokenID callerToken = 0;
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    KITS::ErrorCode errorCode = hceSession->UnRegAllCallback(callerToken);
    ASSERT_TRUE(errorCode == NFC::KITS::ErrorCode::ERR_HCE_PARAMETERS);
}

/**
 * @tc.name: IsDefaultService001
 * @tc.desc: Test HceSessionTest IsDefaultService.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, IsDefaultService001, TestSize.Level1)
{
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    ElementName element;
    const std::string type = "";
    bool isDefaultService = false;
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    KITS::ErrorCode errorCode = hceSession->IsDefaultService(element, type, isDefaultService);
    ASSERT_TRUE(errorCode == NFC::KITS::ErrorCode::ERR_HCE_PARAMETERS);
}

/**
 * @tc.name: IsDefaultService002
 * @tc.desc: Test HceSessionTest IsDefaultService.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, IsDefaultService002, TestSize.Level1)
{
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    nfcService->Initialize();
    ElementName element;
    const std::string type = "";
    bool isDefaultService = false;
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    KITS::ErrorCode errorCode = hceSession->IsDefaultService(element, type, isDefaultService);
    ASSERT_TRUE(errorCode == NFC::KITS::ErrorCode::ERR_NONE);
}

/**
 * @tc.name: HandleWhenRemoteDie001
 * @tc.desc: Test HceSessionTest HandleWhenRemoteDie.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, HandleWhenRemoteDie001, TestSize.Level1)
{
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    Security::AccessToken::AccessTokenID callerToken = 0;
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    KITS::ErrorCode errorCode = hceSession->HandleWhenRemoteDie(callerToken);
    ASSERT_TRUE(errorCode == NFC::KITS::ErrorCode::ERR_HCE_PARAMETERS);
}

/**
 * @tc.name: HandleWhenRemoteDie002
 * @tc.desc: Test HceSessionTest HandleWhenRemoteDie.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, HandleWhenRemoteDie002, TestSize.Level1)
{
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    nfcService->Initialize();
    Security::AccessToken::AccessTokenID callerToken = 0;
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    KITS::ErrorCode errorCode = hceSession->HandleWhenRemoteDie(callerToken);
    ASSERT_TRUE(errorCode == NFC::KITS::ErrorCode::ERR_HCE_PARAMETERS);
}

/**
 * @tc.name: StartHce001
 * @tc.desc: Test HceSessionTest StartHce.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, StartHce001, TestSize.Level1)
{
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    ElementName element;
    std::vector<std::string> aids;
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    KITS::ErrorCode errorCode = hceSession->StartHce(element, aids);
    ASSERT_TRUE(errorCode == NFC::KITS::ErrorCode::ERR_HCE_PARAMETERS);
}

/**
 * @tc.name: StartHce002
 * @tc.desc: Test HceSessionTest StartHce.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, StartHce002, TestSize.Level1)
{
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    nfcService->Initialize();
    ElementName element;
    std::vector<std::string> aids;
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    KITS::ErrorCode errorCode = hceSession->StartHce(element, aids);
    ASSERT_TRUE(errorCode == NFC::KITS::ErrorCode::ERR_HCE_PARAMETERS);
}

/**
 * @tc.name: StopHce001
 * @tc.desc: Test HceSessionTest StopHce.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, StopHce001, TestSize.Level1)
{
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    ElementName element;
    Security::AccessToken::AccessTokenID callerToken = 0;
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    KITS::ErrorCode errorCode = hceSession->StopHce(element, callerToken);
    ASSERT_TRUE(errorCode == NFC::KITS::ErrorCode::ERR_HCE_PARAMETERS);
}

/**
 * @tc.name: StopHce002
 * @tc.desc: Test HceSessionTest StopHce.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, StopHce002, TestSize.Level1)
{
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    nfcService->Initialize();
    std::weak_ptr<NFC::CeService> ceService = nfcService->GetCeService();
    ceService.lock()->Initialize();
    ElementName element;
    Security::AccessToken::AccessTokenID callerToken = 0;
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    KITS::ErrorCode errorCode = hceSession->StopHce(element, callerToken);
    ASSERT_TRUE(errorCode == NFC::KITS::ErrorCode::ERR_HCE_PARAMETERS);
}

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: Test HceSessionTest OnRemoteRequest.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, OnRemoteRequest001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::u16string descriptor = u"ohos.nfc.cardemulation.IHceSession";
    data.WriteInterfaceToken(descriptor);
    data.WriteInt32(1);
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    int errorCode = hceSession->OnRemoteRequest(308, data, reply, option);
    ASSERT_TRUE(errorCode == NFC::KITS::ErrorCode::ERR_NFC_PARAMETERS);
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: Test HceSessionTest OnRemoteRequest.
 * @tc.type: FUNC
 */
HWTEST_F(HceSessionTest, OnRemoteRequest002, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::u16string descriptor = u"ohos.nfc.cardemulation.IHceSession";
    data.WriteInterfaceToken(descriptor);
    data.WriteInt32(0);
    std::shared_ptr<OHOS::NFC::NfcService> nfcService = std::make_shared<OHOS::NFC::NfcService>();
    std::shared_ptr<HCE::HceSession> hceSession = std::make_shared<HCE::HceSession>(nfcService);
    int errorCode = hceSession->OnRemoteRequest(308, data, reply, option);
    ASSERT_TRUE(errorCode == NFC::KITS::ErrorCode::ERR_NONE);
}
}
}
}