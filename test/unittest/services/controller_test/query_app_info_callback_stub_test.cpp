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

#include "query_app_info_callback_stub.h"

namespace OHOS {
namespace NFC {
namespace TEST {
using namespace testing::ext;
using namespace OHOS::NFC;
class QueryAppInfoCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

std::vector<AppExecFwk::ElementName> myTagCallback(std::vector<int>)
{
    return std::vector<AppExecFwk::ElementName> {};
}

std::vector<AAFwk::Want> myHceCallback()
{
    return std::vector<AAFwk::Want> {};
}

void QueryAppInfoCallbackStubTest::SetUpTestCase()
{
    std::cout << " SetUpTestCase QueryAppInfoCallbackStubTest." << std::endl;
}

void QueryAppInfoCallbackStubTest::TearDownTestCase()
{
    std::cout << " TearDownTestCase QueryAppInfoCallbackStubTest." << std::endl;
}

void QueryAppInfoCallbackStubTest::SetUp()
{
    std::cout << " SetUp QueryAppInfoCallbackStubTest." << std::endl;
}

void QueryAppInfoCallbackStubTest::TearDown()
{
    std::cout << " TearDown QueryAppInfoCallbackStubTest." << std::endl;
}

#ifdef VENDOR_APPLICATIONS_ENABLED
/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: Test QueryAppInfoCallbackStubTest OnRemoteRequest.
 * @tc.type: FUNC
 */
HWTEST_F(QueryAppInfoCallbackStubTest, OnRemoteRequest001, TestSize.Level1)
{
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::shared_ptr<QueryAppInfoCallbackStub> queryAppInfoCallbackStub = std::make_shared<QueryAppInfoCallbackStub>();
    int onRemoteRequest = queryAppInfoCallbackStub->OnRemoteRequest(code, data, reply, option);
    ASSERT_TRUE(onRemoteRequest == KITS::ERR_NFC_PARAMETERS);
}

/**
 * @tc.name: RegisterQueryTagAppCallback001
 * @tc.desc: Test QueryAppInfoCallbackStubTest RegisterQueryTagAppCallback.
 * @tc.type: FUNC
 */
HWTEST_F(QueryAppInfoCallbackStubTest, RegisterQueryTagAppCallback001, TestSize.Level1)
{
    QueryApplicationByVendor tagCallback = nullptr;
    std::shared_ptr<QueryAppInfoCallbackStub> queryAppInfoCallbackStub = std::make_shared<QueryAppInfoCallbackStub>();
    KITS::ErrorCode ret = queryAppInfoCallbackStub->RegisterQueryTagAppCallback(tagCallback);
    ASSERT_TRUE(ret == KITS::ERR_NFC_PARAMETERS);
}

/**
 * @tc.name: RegisterQueryTagAppCallback002
 * @tc.desc: Test QueryAppInfoCallbackStubTest RegisterQueryTagAppCallback.
 * @tc.type: FUNC
 */
HWTEST_F(QueryAppInfoCallbackStubTest, RegisterQueryTagAppCallback002, TestSize.Level1)
{
    QueryApplicationByVendor tagCallback = myTagCallback;
    std::shared_ptr<QueryAppInfoCallbackStub> queryAppInfoCallbackStub = std::make_shared<QueryAppInfoCallbackStub>();
    KITS::ErrorCode ret = queryAppInfoCallbackStub->RegisterQueryTagAppCallback(tagCallback);
    ASSERT_TRUE(ret == KITS::ERR_NONE);
}

/**
 * @tc.name: RegisterQueryTagAppCallback003
 * @tc.desc: Test QueryAppInfoCallbackStubTest RegisterQueryTagAppCallback.
 * @tc.type: FUNC
 */
HWTEST_F(QueryAppInfoCallbackStubTest, RegisterQueryTagAppCallback003, TestSize.Level1)
{
    QueryApplicationByVendor tagCallback = myTagCallback;
    std::shared_ptr<QueryAppInfoCallbackStub> queryAppInfoCallbackStub = std::make_shared<QueryAppInfoCallbackStub>();
    queryAppInfoCallbackStub->RegisterQueryTagAppCallback(tagCallback);
    KITS::ErrorCode ret = queryAppInfoCallbackStub->RegisterQueryTagAppCallback(tagCallback);
    ASSERT_TRUE(ret == KITS::ERR_NFC_PARAMETERS);
}

/**
 * @tc.name: RegisterQueryHceAppCallback001
 * @tc.desc: Test QueryAppInfoCallbackStubTest RegisterQueryHceAppCallback.
 * @tc.type: FUNC
 */
HWTEST_F(QueryAppInfoCallbackStubTest, RegisterQueryHceAppCallback001, TestSize.Level1)
{
    QueryHceAppByVendor hceCallback = nullptr;
    std::shared_ptr<QueryAppInfoCallbackStub> queryAppInfoCallbackStub = std::make_shared<QueryAppInfoCallbackStub>();
    KITS::ErrorCode ret = queryAppInfoCallbackStub->RegisterQueryHceAppCallback(hceCallback);
    ASSERT_TRUE(ret == KITS::ERR_NFC_PARAMETERS);
}

/**
 * @tc.name: RegisterQueryHceAppCallback002
 * @tc.desc: Test QueryAppInfoCallbackStubTest RegisterQueryHceAppCallback.
 * @tc.type: FUNC
 */
HWTEST_F(QueryAppInfoCallbackStubTest, RegisterQueryHceAppCallback002, TestSize.Level1)
{
    QueryHceAppByVendor hceCallback = myHceCallback;
    std::shared_ptr<QueryAppInfoCallbackStub> queryAppInfoCallbackStub = std::make_shared<QueryAppInfoCallbackStub>();
    KITS::ErrorCode ret = queryAppInfoCallbackStub->RegisterQueryHceAppCallback(hceCallback);
    ASSERT_TRUE(ret == KITS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest0001
 * @tc.desc: Test QueryAppInfoCallbackStubTest OnRemoteRequest.
 * @tc.type: FUNC
 */
HWTEST_F(QueryAppInfoCallbackStubTest, OnRemoteRequest0001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::shared_ptr<QueryAppInfoCallbackStub> queryAppInfoCallbackStub = std::make_shared<QueryAppInfoCallbackStub>();
    int ret = queryAppInfoCallbackStub->OnRemoteRequest(0, data, reply, option);
    ASSERT_TRUE(ret == KITS::ERR_NFC_PARAMETERS);
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: Test QueryAppInfoCallbackStubTest OnRemoteRequest.
 * @tc.type: FUNC
 */
HWTEST_F(QueryAppInfoCallbackStubTest, OnRemoteRequest002, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::u16string descriptor = u"ohos.nfc.IQueryAppInfoCallback";
    data.WriteInterfaceToken(descriptor);
    data.WriteInt32(1);
    std::shared_ptr<QueryAppInfoCallbackStub> queryAppInfoCallbackStub = std::make_shared<QueryAppInfoCallbackStub>();
    int ret = queryAppInfoCallbackStub->OnRemoteRequest(0, data, reply, option);
    ASSERT_TRUE(ret == 1);
}

/**
 * @tc.name: OnRemoteRequest003
 * @tc.desc: Test QueryAppInfoCallbackStubTest OnRemoteRequest.
 * @tc.type: FUNC
 */
HWTEST_F(QueryAppInfoCallbackStubTest, OnRemoteRequest003, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::u16string descriptor = u"ohos.nfc.IQueryAppInfoCallback";
    data.WriteInterfaceToken(descriptor);
    data.WriteInt32(0);
    std::shared_ptr<QueryAppInfoCallbackStub> queryAppInfoCallbackStub = std::make_shared<QueryAppInfoCallbackStub>();
    int ret = queryAppInfoCallbackStub->OnRemoteRequest(0, data, reply, option);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: OnRemoteRequest004
 * @tc.desc: Test QueryAppInfoCallbackStubTest OnRemoteRequest.
 * @tc.type: FUNC
 */
HWTEST_F(QueryAppInfoCallbackStubTest, OnRemoteRequest004, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::u16string descriptor = u"ohos.nfc.IQueryAppInfoCallback";
    data.WriteInterfaceToken(descriptor);
    data.WriteInt32(0);
    std::shared_ptr<QueryAppInfoCallbackStub> queryAppInfoCallbackStub = std::make_shared<QueryAppInfoCallbackStub>();
    int ret = queryAppInfoCallbackStub->OnRemoteRequest(114, data, reply, option);
    ASSERT_TRUE(!ret);
}

/**
 * @tc.name: OnRemoteRequest005
 * @tc.desc: Test QueryAppInfoCallbackStubTest OnRemoteRequest.
 * @tc.type: FUNC
 */
HWTEST_F(QueryAppInfoCallbackStubTest, OnRemoteRequest005, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::u16string descriptor = u"ohos.nfc.IQueryAppInfoCallback";
    data.WriteInterfaceToken(descriptor);
    data.WriteInt32(0);
    data.WriteString("tag");
    std::shared_ptr<QueryAppInfoCallbackStub> queryAppInfoCallbackStub = std::make_shared<QueryAppInfoCallbackStub>();
    int ret = queryAppInfoCallbackStub->OnRemoteRequest(114, data, reply, option);
    ASSERT_TRUE(!ret);
}

/**
 * @tc.name: OnRemoteRequest007
 * @tc.desc: Test QueryAppInfoCallbackStubTest OnRemoteRequest.
 * @tc.type: FUNC
 */
HWTEST_F(QueryAppInfoCallbackStubTest, OnRemoteRequest007, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::u16string descriptor = u"ohos.nfc.IQueryAppInfoCallback";
    data.WriteInterfaceToken(descriptor);
    data.WriteInt32(0);
    data.WriteString("hce");
    std::shared_ptr<QueryAppInfoCallbackStub> queryAppInfoCallbackStub = std::make_shared<QueryAppInfoCallbackStub>();
    int ret = queryAppInfoCallbackStub->OnRemoteRequest(114, data, reply, option);
    ASSERT_TRUE(!ret);
}
#endif
}
}
}